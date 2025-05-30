
import React from "react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Check, User, School, Vote } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import CandidateCard from "@/components/CandidateCard";

interface VoterConfirmationProps {
  candidateId: string;
  candidateData: any; // Candidate data
  onConfirm: () => void;
  onCancel: () => void;
  isLoading?: boolean;
}

const VoterConfirmation = ({ 
  candidateId,
  candidateData,
  onConfirm,
  onCancel,
  isLoading = false
}: VoterConfirmationProps) => {
  const { currentUser } = useAuth();
  
  if (!currentUser) return null;
  
  return (
    <Card className="w-full max-w-md mx-auto border-0 shadow-lg overflow-hidden bg-gradient-to-br from-white to-vote-light">
      <CardHeader className="bg-white border-b">
        <CardTitle className="text-center text-vote-primary flex items-center justify-center">
          <Check className="mr-2 h-5 w-5 text-vote-primary" />
          Confirm Your Vote
        </CardTitle>
        <CardDescription className="text-center">
          Please review your details and voting selection
        </CardDescription>
      </CardHeader>
      
      <CardContent className="p-6 space-y-6">
        {/* Voter Information Section */}
        <div className="bg-vote-light rounded-lg p-4">
          <h3 className="font-medium text-vote-primary mb-2 flex items-center">
            <User className="h-4 w-4 mr-2" />
            Voter Information
          </h3>
          
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-gray-600">Name:</span>
              <span className="font-medium">{currentUser.name}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-600">Student ID:</span>
              <span className="font-medium">{currentUser.studentId}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-600">Email:</span>
              <span className="font-medium">{currentUser.email}</span>
            </div>
            <div className="flex items-center text-sm text-green-600 mt-1">
              <Check className="h-4 w-4 mr-1" />
              <span>Identity verified with biometric authentication</span>
            </div>
          </div>
        </div>
        
        {/* Candidate Selection Section */}
        <div>
          <h3 className="font-medium text-vote-primary mb-2 flex items-center">
            <Vote className="h-4 w-4 mr-2" />
            Selected Candidate
          </h3>
          
          <div className="mt-2">
            {candidateData && (
              <CandidateCard
                {...candidateData}
                isSelected={true}
              />
            )}
          </div>
        </div>
        
        {/* Vote Confirmation Message */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 text-sm text-blue-700">
          <p>
            By clicking "Confirm Vote", your vote will be recorded on the blockchain and cannot be changed.
            This ensures your vote is secure and immutable.
          </p>
        </div>
      </CardContent>
      
      <CardFooter className="flex justify-center space-x-4 bg-white border-t p-4">
        <Button 
          variant="outline" 
          onClick={onCancel}
          className="border-vote-primary text-vote-primary hover:bg-vote-primary hover:text-white"
          disabled={isLoading}
        >
          Change Selection
        </Button>
        <Button 
          onClick={onConfirm}
          className="bg-gradient-to-r from-vote-primary to-vote-secondary hover:opacity-90 text-white"
          disabled={isLoading}
        >
          {isLoading ? (
            <>
              <span className="animate-spin mr-2">●</span>
              Recording Vote...
            </>
          ) : (
            "Confirm Vote"
          )}
        </Button>
      </CardFooter>
    </Card>
  );
};

export default VoterConfirmation;
