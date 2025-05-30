
import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import Layout from "@/components/Layout";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { User, Check, Fingerprint } from "lucide-react";
import { toast } from "sonner";
import BiometricVerification from "@/components/BiometricVerification";

const Register = () => {
  const [name, setName] = useState<string>("");
  const [email, setEmail] = useState<string>("");
  const [studentId, setStudentId] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [confirmPassword, setConfirmPassword] = useState<string>("");
  const [showBiometricModal, setShowBiometricModal] = useState<boolean>(false);
  const [biometricVerified, setBiometricVerified] = useState<boolean>(false);
  const [registrationStep, setRegistrationStep] = useState<"details" | "biometric" | "completed">("details");
  
  const { register, isLoading } = useAuth();
  const navigate = useNavigate();

  const validateForm = () => {
    if (!name || !email || !studentId || !password || !confirmPassword) {
      toast.error("Please fill out all fields");
      return false;
    }
    
    if (!email.includes('@')) {
      toast.error("Please enter a valid email address");
      return false;
    }
    
    if (password !== confirmPassword) {
      toast.error("Passwords don't match");
      return false;
    }
    
    if (password.length < 6) {
      toast.error("Password must be at least 6 characters");
      return false;
    }
    
    return true;
  };

  const handleNextStep = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }
    
    setRegistrationStep("biometric");
    setShowBiometricModal(true);
  };

  const handleBiometricSuccess = () => {
    setBiometricVerified(true);
    setShowBiometricModal(false);
    setRegistrationStep("completed");
    completeRegistration();
  };

  const completeRegistration = async () => {
    const success = await register({
      name,
      email,
      studentId,
      password
    });
    
    if (success) {
      toast.success("Registration complete with biometric verification!");
      navigate("/");
    }
  };

  return (
    <Layout>
      <div className="min-h-[80vh] flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8 bg-gray-50">
        <Card className="w-full max-w-md border-0 shadow-xl overflow-hidden bg-white">
          <CardHeader className="text-center bg-gradient-to-r from-vote-light to-white border-b pb-8">
            <div className="mx-auto mb-4 h-16 w-16 rounded-full bg-gradient-to-r from-vote-primary to-vote-secondary flex items-center justify-center">
              {registrationStep === "details" ? (
                <User className="h-8 w-8 text-white" />
              ) : registrationStep === "biometric" ? (
                <Fingerprint className="h-8 w-8 text-white" />
              ) : (
                <Check className="h-8 w-8 text-white" />
              )}
            </div>
            <CardTitle className="text-2xl font-bold">
              {registrationStep === "details" 
                ? "Register for VoteGuard" 
                : registrationStep === "biometric" 
                ? "Biometric Setup"
                : "Registration Complete"}
            </CardTitle>
            <CardDescription>
              {registrationStep === "details" 
                ? "Create your account to participate in the election" 
                : registrationStep === "biometric" 
                ? "Set up fingerprint verification for secure voting"
                : "Your account has been created successfully"}
            </CardDescription>
            
            {/* Progress Steps */}
            <div className="flex items-center justify-between mt-6 px-10">
              <div className="flex flex-col items-center">
                <div className={`h-8 w-8 rounded-full flex items-center justify-center ${
                  registrationStep === "details" || registrationStep === "biometric" || registrationStep === "completed" 
                    ? "bg-vote-primary text-white" 
                    : "bg-gray-200 text-gray-500"
                }`}>
                  1
                </div>
                <span className="text-xs mt-1">Details</span>
              </div>
              
              <div className={`h-1 flex-grow mx-2 ${
                registrationStep === "biometric" || registrationStep === "completed" 
                  ? "bg-vote-primary" 
                  : "bg-gray-200"
              }`} />
              
              <div className="flex flex-col items-center">
                <div className={`h-8 w-8 rounded-full flex items-center justify-center ${
                  registrationStep === "biometric" || registrationStep === "completed" 
                    ? "bg-vote-primary text-white" 
                    : "bg-gray-200 text-gray-500"
                }`}>
                  2
                </div>
                <span className="text-xs mt-1">Biometric</span>
              </div>
              
              <div className={`h-1 flex-grow mx-2 ${
                registrationStep === "completed" 
                  ? "bg-vote-primary" 
                  : "bg-gray-200"
              }`} />
              
              <div className="flex flex-col items-center">
                <div className={`h-8 w-8 rounded-full flex items-center justify-center ${
                  registrationStep === "completed" 
                    ? "bg-vote-primary text-white" 
                    : "bg-gray-200 text-gray-500"
                }`}>
                  3
                </div>
                <span className="text-xs mt-1">Complete</span>
              </div>
            </div>
          </CardHeader>
          
          {registrationStep === "details" && (
            <form onSubmit={handleNextStep}>
              <CardContent className="space-y-4 pt-6">
                <div className="space-y-2">
                  <label htmlFor="name" className="text-sm font-medium text-gray-700">
                    Full Name
                  </label>
                  <Input
                    id="name"
                    placeholder="John Doe"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    autoComplete="name"
                    className="w-full"
                  />
                </div>
                
                <div className="space-y-2">
                  <label htmlFor="email" className="text-sm font-medium text-gray-700">
                    Academic Email
                  </label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="your.name@university.edu"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    autoComplete="email"
                    className="w-full"
                  />
                </div>
                
                <div className="space-y-2">
                  <label htmlFor="studentId" className="text-sm font-medium text-gray-700">
                    Student ID
                  </label>
                  <Input
                    id="studentId"
                    placeholder="S12345"
                    value={studentId}
                    onChange={(e) => setStudentId(e.target.value)}
                    className="w-full"
                  />
                </div>
                
                <div className="space-y-2">
                  <label htmlFor="password" className="text-sm font-medium text-gray-700">
                    Password
                  </label>
                  <Input
                    id="password"
                    type="password"
                    placeholder="••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="new-password"
                    className="w-full"
                  />
                </div>
                
                <div className="space-y-2">
                  <label htmlFor="confirmPassword" className="text-sm font-medium text-gray-700">
                    Confirm Password
                  </label>
                  <Input
                    id="confirmPassword"
                    type="password"
                    placeholder="••••••••"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    autoComplete="new-password"
                    className="w-full"
                  />
                </div>
                
                <div className="flex items-center">
                  <div className="h-5 w-5 rounded border border-vote-primary flex items-center justify-center mr-2 bg-vote-primary">
                    <Check className="h-3 w-3 text-white" />
                  </div>
                  <label htmlFor="terms" className="text-sm text-gray-500">
                    I agree to the <a href="#" className="text-vote-primary hover:text-vote-secondary">Terms of Service</a> and <a href="#" className="text-vote-primary hover:text-vote-secondary">Privacy Policy</a>
                  </label>
                </div>
              </CardContent>
              
              <CardFooter className="flex flex-col space-y-4 border-t p-6 bg-gray-50">
                <Button
                  type="submit"
                  className="w-full bg-gradient-to-r from-vote-primary to-vote-secondary hover:opacity-90 text-white"
                >
                  Continue to Biometric Setup
                </Button>
                
                <div className="text-sm text-center">
                  Already have an account?{" "}
                  <Link to="/login" className="font-medium text-vote-primary hover:text-vote-secondary">
                    Login instead
                  </Link>
                </div>
              </CardFooter>
            </form>
          )}
          
          {registrationStep === "completed" && (
            <CardContent className="space-y-6 p-8 text-center">
              <div className="mx-auto h-20 w-20 rounded-full bg-green-100 flex items-center justify-center">
                <Check className="h-10 w-10 text-green-600" />
              </div>
              
              <div>
                <h3 className="text-xl font-medium mb-2">Registration Complete!</h3>
                <p className="text-gray-600">
                  Your account has been created with biometric verification.
                  You can now log in and participate in elections.
                </p>
              </div>
              
              <div className="pt-4">
                <Button
                  className="bg-gradient-to-r from-vote-primary to-vote-secondary hover:opacity-90 text-white"
                  onClick={() => navigate("/")}
                >
                  Go to Homepage
                </Button>
              </div>
            </CardContent>
          )}
        </Card>
      </div>
      
      {/* Biometric Modal */}
      {showBiometricModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="w-full max-w-md">
            <BiometricVerification
              onVerified={handleBiometricSuccess}
              onCancel={() => {
                setShowBiometricModal(false);
                setRegistrationStep("details");
              }}
            />
          </div>
        </div>
      )}
    </Layout>
  );
};

export default Register;
