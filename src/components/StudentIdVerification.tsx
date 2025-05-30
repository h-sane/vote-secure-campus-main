
import React, { useState } from "react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { IdCard, Check, AlertCircle } from "lucide-react";
import { toast } from "sonner";
import { useAuth } from "@/context/AuthContext";

interface StudentIdVerificationProps {
  onVerified: () => void;
  onCancel: () => void;
}

const StudentIdVerification = ({ onVerified, onCancel }: StudentIdVerificationProps) => {
  const [studentId, setStudentId] = useState<string>("");
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const { currentUser, verifyStudentId } = useAuth();

  const handleVerify = async () => {
    if (!studentId.trim()) {
      toast.error("Please enter your Student ID");
      return;
    }

    setIsVerifying(true);

    try {
      const isValid = await verifyStudentId(studentId);
      
      if (isValid) {
        toast.success("Student ID verified successfully!");
        onVerified();
      } else {
        toast.error("Invalid Student ID. Please try again.");
      }
    } catch (error) {
      console.error("Error verifying student ID:", error);
      toast.error("Error verifying Student ID. Please try again.");
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <Card className="w-full max-w-md mx-auto border-0 shadow-lg overflow-hidden bg-gradient-to-br from-white to-vote-light">
      <CardHeader className="bg-white border-b">
        <CardTitle className="text-center text-vote-primary flex items-center justify-center">
          <IdCard className="mr-2 h-5 w-5 text-vote-primary" />
          Student ID Verification
        </CardTitle>
        <CardDescription className="text-center">
          Please enter your Student ID to proceed with voting
        </CardDescription>
      </CardHeader>
      
      <CardContent className="flex flex-col items-center p-8">
        <div className="w-full space-y-4">
          <div className="mx-auto h-20 w-20 rounded-full bg-vote-light flex items-center justify-center mb-6">
            <IdCard className="h-10 w-10 text-vote-primary" />
          </div>
          
          <div className="space-y-2 w-full">
            <label htmlFor="studentId" className="text-sm font-medium text-gray-700">
              Student ID
            </label>
            <Input
              id="studentId"
              placeholder="Enter your Student ID (e.g. S12345)"
              value={studentId}
              onChange={(e) => setStudentId(e.target.value)}
              className="w-full"
              disabled={isVerifying}
            />
          </div>
          
          <div className="bg-vote-light border border-vote-accent p-3 rounded-lg">
            <p className="text-sm text-gray-600">
              Your Student ID is required to verify your eligibility to vote.
            </p>
          </div>

          {currentUser?.studentId && studentId && currentUser.studentId !== studentId && (
            <div className="flex items-center bg-amber-50 text-amber-700 p-3 rounded-lg">
              <AlertCircle className="h-5 w-5 mr-2 text-amber-500" />
              <p className="text-sm">
                Warning: This Student ID does not match the one used for registration.
              </p>
            </div>
          )}
        </div>
      </CardContent>
      
      <CardFooter className="flex justify-center space-x-4 bg-white border-t p-4">
        <Button 
          variant="outline" 
          onClick={onCancel}
          className="border-vote-primary text-vote-primary hover:bg-vote-primary hover:text-white"
          disabled={isVerifying}
        >
          Cancel
        </Button>
        <Button 
          onClick={handleVerify}
          className="bg-gradient-to-r from-vote-primary to-vote-secondary hover:opacity-90 text-white"
          disabled={isVerifying}
        >
          {isVerifying ? (
            <>
              <span className="animate-spin mr-2">●</span>
              Verifying...
            </>
          ) : (
            "Verify Student ID"
          )}
        </Button>
      </CardFooter>
    </Card>
  );
};

export default StudentIdVerification;
