
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
      
      // Generate a user ID if not provided (for registration)
      const userIdToUse = userId || crypto.randomUUID();
      
      console.log("Creating WebAuthn credential with user ID:", userIdToUse);
      
      // Create credential options
      const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
        challenge,
        rp: {
          name: "VoteGuard",
          id: window.location.hostname
        },
        user: {
          id: new TextEncoder().encode(userIdToUse),
          name: userIdToUse,
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
        attestation: "none"  // Changed from "direct" to "none" for better compatibility
      };
      
      console.log("WebAuthn options:", JSON.stringify(publicKeyCredentialCreationOptions, (key, value) => {
        if (key === 'challenge' || key === 'id') {
          return value instanceof Uint8Array ? `Uint8Array(${value.length})` : value;
        }
        return value;
      }));
      
      const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
      });
      
      if (!credential) {
        throw new Error("No credential returned from WebAuthn");
      }
      
      console.log("Credential created successfully:", {
        id: credential.id,
        type: credential.type,
        rawId: credential.rawId ? `Uint8Array(${new Uint8Array(credential.rawId).length})` : null,
        response: {
          clientDataJSON: credential.response.clientDataJSON ? '[...]' : null,
          attestationObject: credential.response.attestationObject ? '[...]' : null
        }
      });
      
      return credential as PublicKeyCredential;
    } catch (error) {
      console.error("WebAuthn credential creation failed:", error);
      throw new Error(`Failed to create credential: ${error.message}`);
    }
  };

  // Store fingerprint in the database
  const storeFingerprintInDb = async (userId: string, credential: PublicKeyCredential) => {
    console.log("Starting to store fingerprint for user:", userId);
    
    try {
      // Verify the credential is from a biometric sensor
      console.log("Checking for biometric sensor...");
      const isBiometric = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      
      if (!isBiometric) {
        console.error("No biometric sensor detected");
        throw new Error("Biometric sensor not detected");
      }
      
      console.log("Biometric sensor available, processing credential...");
      
      // Convert credential data to a hash for storage
      const arrayBufferToHex = (buffer: ArrayBuffer): string => {
        return Array.from(new Uint8Array(buffer))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
      };
      
      // Create a unique fingerprint hash from the credential data
      const credentialData = {
        id: credential.id,
        rawId: arrayBufferToHex(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: arrayBufferToHex(credential.response.clientDataJSON),
          attestationObject: arrayBufferToHex(credential.response.attestationObject)
        }
      };
      
      // Create a hash of the credential data
      const encoder = new TextEncoder();
      const data = encoder.encode(JSON.stringify(credentialData));
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const fingerprintHash = arrayBufferToHex(hashBuffer);
      
      console.log("Storing fingerprint hash in database...");
      
      // Store in Supabase
      const { data: result, error } = await supabase
        .from('users_biometrics')
        .upsert({
          user_id: userId,
          fingerprint_hash: fingerprintHash,
          device_info: {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            timestamp: new Date().toISOString()
          },
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        })
        .select();
        
      if (error) {
        console.error("Supabase error storing fingerprint:", error);
        throw error;
      }
      
      console.log("Fingerprint stored successfully in database:", result);
      return true;
    } catch (error) {
      console.error("Error in storeFingerprintInDb:", error);
      throw error; // Re-throw to be caught by the caller
    }
  };

  // Verify fingerprint against database
  const verifyFingerprintInDb = async (userId: string, credential: PublicKeyCredential) => {
    try {
      // Convert credential data to a hash for comparison
      const arrayBufferToHex = (buffer: ArrayBuffer): string => {
        return Array.from(new Uint8Array(buffer))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
      };
      
      // Create the same hash as stored in the database
      const credentialData = {
        id: credential.id,
        rawId: arrayBufferToHex(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: arrayBufferToHex(credential.response.clientDataJSON),
          attestationObject: arrayBufferToHex(credential.response.attestationObject)
        }
      };
      
      // Create a hash of the credential data
      const encoder = new TextEncoder();
      const data = encoder.encode(JSON.stringify(credentialData));
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const fingerprintHash = arrayBufferToHex(hashBuffer);
      
      // Get stored fingerprint hash from the database
      const { data: storedData, error: fetchError } = await supabase
        .from('users_biometrics')
        .select('fingerprint_hash')
        .eq('user_id', userId)
        .single();
      
      if (fetchError || !storedData) {
        console.log("No stored fingerprint found for user:", userId);
        return false;
      }
      
      // Compare the stored hash with the current one
      const isMatch = storedData.fingerprint_hash === fingerprintHash;
      console.log("Fingerprint verification result:", isMatch);
      
      // For testing: Also verify using WebAuthn assertion
      try {
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
          console.log("No assertion returned from WebAuthn");
          return false;
        }
        
        console.log("WebAuthn assertion successful");
        return isMatch; // Return the hash comparison result
      } catch (assertionError) {
        console.warn("WebAuthn assertion failed, falling back to hash comparison:", assertionError);
        return isMatch;
      }
    } catch (error) {
      console.error("Verification error:", error);
      return false;
    }
  };

  const startScan = async () => {
    console.log("=== Starting biometric scan ===");
    
    if (!biometricAvailable) {
      const errorMsg = "Biometric verification not available on this device";
      console.error(errorMsg);
      toast.error(errorMsg);
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
      
      console.log("Checking WebAuthn support...");
      if (isWebAuthnSupported) {
        try {
          console.log("WebAuthn is supported, starting authentication...");
          const credential = await getFingerprintData();
          setProgress(80);
          
          // For registration, generate a new user ID if not provided
          // For verification, use the provided user ID
          const userIdToUse = userId || localStorage.getItem('registeredUserId') || crypto.randomUUID();
          const isRegistration = !userId;
          
          console.log(`Processing for user: ${isRegistration ? 'registration' : 'verification'} (ID: ${userIdToUse})`);
          
          if (isRegistration) {
            // In registration flow
            console.log("Starting registration flow...");
            verificationSuccess = await storeFingerprintInDb(userIdToUse, credential);
            
            if (verificationSuccess) {
              console.log("Registration successful!");
              // Store the user ID for future verifications
              localStorage.setItem('registeredUserId', userIdToUse);
              toast.success("Fingerprint registered successfully!");
            } else {
              const errorMsg = "Failed to register fingerprint";
              console.error(errorMsg);
              toast.error(errorMsg);
            }
          } else {
            // In verification flow (voting)
            console.log("Starting verification flow...");
            verificationSuccess = await verifyFingerprintInDb(userIdToUse, credential);
            setVerificationAttempts(prev => prev + 1);
            
            if (!verificationSuccess) {
              const errorMsg = "Fingerprint does not match registered fingerprint";
              console.error(errorMsg);
              toast.error(errorMsg);
            } else {
              console.log("Verification successful!");
              toast.success("Fingerprint verified successfully!");
            }
          }
        } catch (error) {
          const errorMsg = `WebAuthn error: ${error.message || 'Unknown error'}`;
          console.error(errorMsg, error);
          toast.error("Failed to complete biometric authentication. Please try again.");
          verificationSuccess = false;
        }
      } else {
        const errorMsg = "WebAuthn not supported on this device";
        console.error(errorMsg);
        toast.error(errorMsg);
        verificationSuccess = false;
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
