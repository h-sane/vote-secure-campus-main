
import React, { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Fingerprint, CheckCircle2, AlertCircle, Smartphone, Wifi, WifiOff } from "lucide-react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { useIsMobile } from "@/hooks/use-mobile";

interface BiometricVerificationProps {
  onVerified: () => void;
  onCancel: () => void;
  userId?: string;
}

const BiometricVerification = ({ onVerified, onCancel, userId }: BiometricVerificationProps) => {
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [biometricAvailable, setBiometricAvailable] = useState<boolean | null>(null);
  const [verificationAttempts, setVerificationAttempts] = useState<number>(0);
  const [isWebAuthnSupported, setIsWebAuthnSupported] = useState<boolean>(false);
  const [deviceCapabilities, setDeviceCapabilities] = useState<{
    isMobile: boolean;
    hasBiometrics: boolean;
    hasWebAuthn: boolean;
    networkOnline: boolean;
  }>({
    isMobile: false,
    hasBiometrics: false,
    hasWebAuthn: false,
    networkOnline: true
  });
  
  const isMobile = useIsMobile();
  
  // Check if biometric authentication is available
  useEffect(() => {
    const checkBiometricAvailability = async () => {
      try {
        // Check network status
        const isOnline = navigator.onLine;
        
        // Check if running in a mobile browser
        const isMobileDevice = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
        
        // Check for WebAuthn support
        const hasWebAuthn = window.PublicKeyCredential !== undefined;
        
        let hasBiometricCapability = false;
        
        if (hasWebAuthn && PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
          try {
            hasBiometricCapability = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
            setIsWebAuthnSupported(true);
          } catch (error) {
            console.warn("Error checking platform authenticator:", error);
            hasBiometricCapability = false;
          }
        }
        
        setDeviceCapabilities({
          isMobile: isMobileDevice,
          hasBiometrics: hasBiometricCapability,
          hasWebAuthn: hasWebAuthn,
          networkOnline: isOnline
        });
        
        // Only allow biometric verification if we have proper biometric capability
        setBiometricAvailable(hasBiometricCapability);
        
        if (!hasBiometricCapability) {
          toast.error("No biometric sensor detected. Please use a device with fingerprint scanner.");
        }
      } catch (error) {
        console.error("Error during biometric capability check:", error);
        setBiometricAvailable(false);
      }
    };
    
    checkBiometricAvailability();
    
    // Monitor network status
    const handleOnline = () => {
      setDeviceCapabilities(prev => ({ ...prev, networkOnline: true }));
    };
    
    const handleOffline = () => {
      setDeviceCapabilities(prev => ({ ...prev, networkOnline: false }));
    };
    
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    
    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  // Get fingerprint data using WebAuthn
  const getFingerprintData = async (): Promise<PublicKeyCredential> => {
    if (!window.PublicKeyCredential) {
      throw new Error("WebAuthn is not supported in this browser");
    }
    
    try {
      // Create a secure challenge
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      
      // Create credential options
      const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
        challenge,
        rp: {
          name: "VoteGuard",
          id: window.location.hostname
        },
        user: {
          id: new TextEncoder().encode(userId || crypto.randomUUID()),
          name: userId || crypto.randomUUID(),
          displayName: userId ? "Registered User" : "New Registration"
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 }, // ES256
          { type: "public-key", alg: -257 } // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          userVerification: "required",
          requireResidentKey: true
        },
        timeout: 60000,
        attestation: "direct"
      };
      
      console.log("Starting WebAuthn credential creation");
      
      const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
      });
      
      if (!credential) {
        throw new Error("No credential returned");
      }
      
      console.log("Credential created successfully");
      return credential;
    } catch (error) {
      console.error("WebAuthn credential creation error:", error);
      throw error;
    }
  };

  // Store fingerprint in the database
  const storeFingerprintInDb = async (userId: string, credential: PublicKeyCredential) => {
    try {
      // Verify the credential is from a biometric sensor
      const isBiometric = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      
      if (!isBiometric) {
        throw new Error("Biometric sensor not detected");
      }
      
      // Store the credential data
      const credentialData = {
        id: credential.id,
        rawId: Array.from(new Uint8Array(credential.rawId)),
        type: credential.type,
        response: {
          clientDataJSON: Array.from(new Uint8Array(credential.response.clientDataJSON)),
          attestationObject: Array.from(new Uint8Array(credential.response.attestationObject))
        }
      };
      
      // Store in Supabase
      const { error } = await supabase
        .from('users_biometrics')
        .upsert({
          user_id: userId,
          credential_id: credential.id,
          credential_data: credentialData,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        });
        
      if (error) {
        console.error("Supabase error storing fingerprint:", error);
        return false;
      }
      
      console.log("Fingerprint stored successfully");
      return true;
    } catch (error) {
      console.error("Error processing fingerprint:", error);
      return false;
    }
  };

  // Verify fingerprint against database
  const verifyFingerprintInDb = async (userId: string, credential: PublicKeyCredential) => {
    try {
      // Get stored credential
      const { data: storedData, error: fetchError } = await supabase
        .from('users_biometrics')
        .select('credential_data')
        .eq('user_id', userId)
        .single();
      
      if (fetchError || !storedData || !storedData.credential_data) {
        console.log("No stored credential found");
        return false;
      }
      
      // Verify using WebAuthn
      const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{
          type: "public-key",
          id: credential.rawId
        }],
        timeout: 60000,
        userVerification: "required"
      };
      
      const assertion = await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions
      });
      
      if (!assertion) {
        return false;
      }
      
      // Verify the signature
      const response = assertion.response;
      const authData = new Uint8Array(response.authenticatorData);
      const clientDataJSON = new Uint8Array(response.clientDataJSON);
      
      // Verify the response
      const verified = await crypto.subtle.verify(
        'ECDSA',
        storedData.credential_data.publicKey,
        response.signature,
        authData
      );
      
      return verified;
    } catch (error) {
      console.error("Verification error:", error);
      return false;
    }
  };

  const startScan = async () => {
    if (!biometricAvailable) {
      toast.error("Biometric verification not available on this device");
      return;
    }

    setIsScanning(true);
    setProgress(0);
    
    // Set up progress animation
    const progressInterval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 60) {
          clearInterval(progressInterval);
          return 60;
        }
        return prev + 10;
      });
    }, 300);
    
    try {
      let verificationSuccess = false;
      
      // Only use WebAuthn for verification
      if (isWebAuthnSupported) {
        try {
          console.log("Attempting WebAuthn authentication");
          const credential = await getFingerprintData();
          setProgress(80);
          
          if (userId) {
            // In verification flow (voting)
            verificationSuccess = await verifyFingerprintInDb(userId, credential);
            setVerificationAttempts(prev => prev + 1);
            
            if (!verificationSuccess) {
              toast.error("Fingerprint does not match registered fingerprint");
            }
          } else {
            // In registration flow
            verificationSuccess = await storeFingerprintInDb(userId || crypto.randomUUID(), credential);
            
            if (!verificationSuccess) {
              toast.error("Failed to register fingerprint");
            }
          }
        } catch (error) {
          console.error("WebAuthn error:", error);
          toast.error("Failed to authenticate with biometric sensor");
          verificationSuccess = false;
        }
      } else {
        verificationSuccess = false;
        toast.error("WebAuthn not supported on this device");
      }
      
      clearInterval(progressInterval);
      setProgress(100);
      
      setTimeout(() => {
        setIsScanning(false);
        
        if (verificationSuccess) {
          onVerified();
          toast.success(userId ? "Biometric verification successful!" : "Biometric registration successful!");
        }
      }, 500);
      
    } catch (error) {
      console.error("Biometric authentication error:", error);
      clearInterval(progressInterval);
      toast.error("Biometric verification failed");
      setIsScanning(false);
      setProgress(0);
    }
  };

  return (
    <Card className="w-full max-w-md mx-auto border-0 shadow-lg overflow-hidden bg-gradient-to-br from-white to-vote-light">
      <CardHeader className="bg-white border-b">
        <CardTitle className="text-center text-vote-primary flex items-center justify-center">
          <Fingerprint className="mr-2 h-5 w-5 text-vote-primary" />
          Biometric Verification
        </CardTitle>
        <CardDescription className="text-center">
          {biometricAvailable === false 
            ? "Your device doesn't support biometric verification. Using device fingerprinting instead."
            : userId ? "Place your finger on the sensor to verify your identity" : "Register your fingerprint for secure voting"}
        </CardDescription>
        
        {/* Device capability indicators */}
        <div className="flex justify-center items-center gap-2 mt-2">
          <div className="flex items-center text-xs text-gray-500 px-2 py-1 bg-gray-100 rounded-full">
            {deviceCapabilities.isMobile ? (
              <Smartphone className="h-3 w-3 mr-1 text-green-500" />
            ) : (
              <span className="h-3 w-3 mr-1 bg-blue-500 rounded-full"></span>
            )}
            <span>{deviceCapabilities.isMobile ? "Mobile" : "Desktop"}</span>
          </div>
          
          <div className="flex items-center text-xs text-gray-500 px-2 py-1 bg-gray-100 rounded-full">
            {deviceCapabilities.hasBiometrics ? (
              <Fingerprint className="h-3 w-3 mr-1 text-green-500" />
            ) : (
              <Fingerprint className="h-3 w-3 mr-1 text-gray-400" />
            )}
            <span>{deviceCapabilities.hasBiometrics ? "Biometric" : "No Biometric"}</span>
          </div>
          
          <div className="flex items-center text-xs text-gray-500 px-2 py-1 bg-gray-100 rounded-full">
            {deviceCapabilities.networkOnline ? (
              <Wifi className="h-3 w-3 mr-1 text-green-500" />
            ) : (
              <WifiOff className="h-3 w-3 mr-1 text-red-500" />
            )}
            <span>{deviceCapabilities.networkOnline ? "Online" : "Offline"}</span>
          </div>
        </div>
      </CardHeader>
      
      <CardContent className="flex flex-col items-center p-8">
        <div 
          className={`w-36 h-36 rounded-full border-4 ${
            isScanning ? 'border-vote-primary animate-pulse-slow' : 'border-gray-300'
          } flex items-center justify-center mb-6 transition-all relative overflow-hidden`}
        >
          {isScanning && progress >= 100 && (
            <div className="absolute inset-0 bg-vote-primary bg-opacity-20 flex items-center justify-center">
              <CheckCircle2 className="h-12 w-12 text-vote-primary" />
            </div>
          )}
          
          {isScanning && progress < 100 && (
            <div className="absolute inset-0 bg-vote-accent bg-opacity-20 flex flex-col items-center justify-center">
              <span className="text-xs font-medium text-vote-primary mb-2">Scanning...</span>
              <div className="relative w-16 h-16">
                <div className="absolute top-0 left-0 w-full h-full border-4 border-vote-primary border-opacity-25 rounded-full"></div>
                <div 
                  className="absolute top-0 left-0 w-full h-full border-4 border-vote-primary rounded-full border-t-transparent"
                  style={{ 
                    transform: `rotate(${progress * 3.6}deg)`,
                    transition: 'transform 0.3s ease' 
                  }}
                ></div>
              </div>
            </div>
          )}
          
          <Fingerprint 
            className={`h-16 w-16 ${
              isScanning ? 'text-vote-primary' : 'text-gray-400'
            } transition-colors`} 
          />
        </div>
        
        {isScanning && (
          <div className="w-full max-w-xs mb-4">
            <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
              <div 
                className="h-full bg-gradient-to-r from-vote-primary to-vote-secondary transition-all duration-300 rounded-full"
                style={{ width: `${progress}%` }} 
              />
            </div>
            <p className="text-sm text-center mt-2 text-gray-500">
              {progress < 80 ? 'Scanning...' : progress < 100 ? 'Verifying...' : 'Complete!'}
            </p>
          </div>
        )}
        
        {verificationAttempts > 0 && verificationAttempts < 3 && !isScanning && (
          <div className="flex items-center bg-red-50 text-red-700 p-3 rounded-lg mb-4">
            <AlertCircle className="h-5 w-5 mr-2 text-red-500" />
            <p className="text-sm">Verification failed. Please try again.</p>
          </div>
        )}
        
        {!isScanning && biometricAvailable === false && (
          <div className="text-center mb-4 text-sm text-amber-700 bg-amber-50 p-3 rounded-lg">
            <p className="font-medium">Device compatibility note:</p>
            <p>Your device doesn't support native fingerprint scanning.</p>
            <p>We'll use a device ID for verification instead.</p>
          </div>
        )}
      </CardContent>
      
      <CardFooter className="flex justify-center space-x-4 bg-white border-t p-4">
        {!isScanning ? (
          <>
            <Button 
              variant="outline" 
              onClick={onCancel}
              className="border-vote-primary text-vote-primary hover:bg-vote-primary hover:text-white"
            >
              Cancel
            </Button>
            <Button 
              onClick={startScan}
              className="bg-gradient-to-r from-vote-primary to-vote-secondary hover:opacity-90 text-white"
            >
              {userId ? "Verify Fingerprint" : "Register Fingerprint"}
            </Button>
          </>
        ) : (
          <Button 
            variant="outline" 
            onClick={() => {
              setIsScanning(false);
              toast.error("Scan cancelled");
            }}
            className="border-destructive text-destructive hover:bg-destructive hover:text-destructive-foreground"
          >
            Cancel Scan
          </Button>
        )}
      </CardFooter>
    </Card>
  );
};

export default BiometricVerification;
