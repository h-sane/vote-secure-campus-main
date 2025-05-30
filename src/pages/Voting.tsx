import React, { useState, useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom";
import Layout from "@/components/Layout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Shield, Vote, Clock, AlertCircle, Fingerprint } from "lucide-react";
import CandidateCard from "@/components/CandidateCard";
import BiometricVerification from "@/components/BiometricVerification";
import StudentIdVerification from "@/components/StudentIdVerification";
import VoterConfirmation from "@/components/VoterConfirmation";
import { useAuth } from "@/context/AuthContext";
import { useBlockchain } from "@/context/BlockchainContext";
import { toast } from "sonner";

const Voting = () => {
  const [selectedCandidate, setSelectedCandidate] = useState<string | null>(null);
  const [showBiometricModal, setShowBiometricModal] = useState<boolean>(false);
  const [showStudentIdModal, setShowStudentIdModal] = useState<boolean>(false);
  const [votingStep, setVotingStep] = useState<"select" | "studentId" | "verify" | "confirm">("select");
  const [verificationFailed, setVerificationFailed] = useState<boolean>(false);
  
  const { currentUser, isAuthenticated, verifyBiometric, setHasVoted } = useAuth();
  const { castVote, isLoading, getElection, setCurrentElection } = useBlockchain();
  const navigate = useNavigate();
  const { electionId } = useParams<{ electionId?: string }>();
  
  // Load election if ID is provided
  useEffect(() => {
    if (electionId) {
      const election = getElection(electionId);
      if (election) {
        setCurrentElection(electionId);
      } else {
        toast.error("Election not found");
        navigate("/");
      }
    }
  }, [electionId, getElection, setCurrentElection, navigate]);
  
  // Get current election
  const election = electionId ? getElection(electionId) : undefined;
  
  // Get selected candidate data
  const selectedCandidateData = selectedCandidate && election?.candidates 
    ? election.candidates.find(c => c.id === selectedCandidate) 
    : null;
  
  // Check if election has reached vote limit or time limit
  const hasReachedVoteLimit = election?.voteLimit && election.candidates.reduce((sum, c) => sum + c.votes, 0) >= election.voteLimit;
  const isElectionClosed = election?.endTime && new Date(election.endTime) < new Date();
  const isVotingDisabled = hasReachedVoteLimit || isElectionClosed;
  
  // Check if user is authenticated
  useEffect(() => {
    if (!isAuthenticated) {
      toast.error("You must be logged in to vote");
      navigate("/login");
      return;
    }
    
    if (!electionId && currentUser?.hasVoted) {
      toast.error("You have already cast your vote in the default election");
      navigate("/results");
    }
  }, [isAuthenticated, currentUser, navigate, electionId]);

  const handleStudentIdSuccess = () => {
    setShowStudentIdModal(false);
    setVotingStep("verify");
    setShowBiometricModal(true);
    toast.success("Student ID verified!");
  };

  const handleBiometricSuccess = () => {
    setShowBiometricModal(false);
    setVotingStep("confirm");
    toast.success("Biometric verification successful!");
  };

  const handleBiometricFailure = () => {
    setShowBiometricModal(false);
    setVerificationFailed(true);
    toast.error("Biometric verification failed. You are not authorized to vote.");
  };

  const handleVoteSelection = (candidateId: string) => {
    setSelectedCandidate(candidateId);
  };

  const handleProceedToStudentId = () => {
    if (!selectedCandidate) {
      toast.error("Please select a candidate");
      return;
    }
    
    setVotingStep("studentId");
    setShowStudentIdModal(true);
  };

  const handleCastVote = async () => {
    if (!selectedCandidate || !currentUser) return;
    
    const success = await castVote(selectedCandidate, currentUser.id, electionId);
    
    if (success) {
      if (!electionId) {
        // Only mark the user as voted if this is the main election
        setHasVoted();
      }
      toast.success("Your vote has been recorded on the blockchain!");
      navigate(electionId ? `/results/${electionId}` : "/results");
    }
  };

  return (
    <Layout>
      <div className="container mx-auto px-4 py-12">
        <div className="max-w-4xl mx-auto">
          <div className="flex items-center mb-6">
            <div className="h-10 w-10 rounded-full bg-gradient-to-r from-vote-primary to-vote-secondary flex items-center justify-center mr-3">
              <Vote className="h-5 w-5 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-vote-dark">
                {election ? election.title : "Election Ballot"}
              </h1>
              {election?.description && (
                <p className="text-gray-600">{election.description}</p>
              )}
            </div>
          </div>
          
          {isVotingDisabled && (
            <Alert variant="destructive" className="mb-6">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Voting is closed</AlertTitle>
              <AlertDescription>
                {hasReachedVoteLimit 
                  ? "This election has reached its maximum number of votes."
                  : "The voting period for this election has ended."
                }
              </AlertDescription>
            </Alert>
          )}
          
          {/* Election Info Section */}
          <div className="flex flex-col md:flex-row items-start md:items-center md:justify-between mb-8 p-4 rounded-lg bg-vote-light border border-vote-accent">
            {election.voteLimit && (
              <div className="flex items-center mb-2 md:mb-0">
                <Vote className="h-5 w-5 text-vote-primary mr-2" />
                <span className="text-sm text-gray-700">
                  Vote Limit: {election.candidates.reduce((sum, c) => sum + c.votes, 0)} / {election.voteLimit}
                </span>
              </div>
            )}
            
            {election.endTime && (
              <div className="flex items-center">
                <Clock className="h-5 w-5 text-vote-primary mr-2" />
                <span className="text-sm text-gray-700">
                  Closes: {new Date(election.endTime).toLocaleString()}
                </span>
              </div>
            )}
          </div>
          
          {/* Progress Steps */}
          <div className="flex items-center justify-between mb-8 px-4 bg-white p-4 rounded-xl shadow-sm">
            <div className="flex flex-col items-center">
              <div className={`h-10 w-10 rounded-full flex items-center justify-center ${
                votingStep === "select" 
                  ? "bg-gradient-to-r from-vote-primary to-vote-secondary text-white" 
                  : "bg-vote-primary text-white"
              }`}>
                1
              </div>
              <span className="text-xs mt-1">Select</span>
            </div>
            
            <div className={`h-1 flex-grow mx-2 ${votingStep === "select" ? "bg-gray-200" : "bg-vote-primary"}`} />
            
            <div className="flex flex-col items-center">
              <div className={`h-10 w-10 rounded-full flex items-center justify-center ${
                votingStep === "studentId" || votingStep === "verify" || votingStep === "confirm"
                  ? "bg-gradient-to-r from-vote-primary to-vote-secondary text-white" 
                  : "bg-gray-200 text-gray-500"
              }`}>
                2
              </div>
              <span className="text-xs mt-1">ID</span>
            </div>
            
            <div className={`h-1 flex-grow mx-2 ${
              votingStep === "verify" || votingStep === "confirm" ? "bg-vote-primary" : "bg-gray-200"
            }`} />
            
            <div className="flex flex-col items-center">
              <div className={`h-10 w-10 rounded-full flex items-center justify-center ${
                votingStep === "verify" || votingStep === "confirm" 
                  ? "bg-gradient-to-r from-vote-primary to-vote-secondary text-white" 
                  : "bg-gray-200 text-gray-500"
              }`}>
                3
              </div>
              <span className="text-xs mt-1">Verify</span>
            </div>
            
            <div className={`h-1 flex-grow mx-2 ${votingStep === "confirm" ? "bg-vote-primary" : "bg-gray-200"}`} />
            
            <div className="flex flex-col items-center">
              <div className={`h-10 w-10 rounded-full flex items-center justify-center ${
                votingStep === "confirm" 
                  ? "bg-gradient-to-r from-vote-primary to-vote-secondary text-white" 
                  : "bg-gray-200 text-gray-500"
              }`}>
                4
              </div>
              <span className="text-xs mt-1">Submit</span>
            </div>
          </div>
          
          {/* Voting Interface */}
          {votingStep === "select" && (
            <Card className="border-0 shadow-lg overflow-hidden bg-gradient-to-br from-white to-vote-light">
              <CardHeader className="bg-white border-b">
                <CardTitle>Select Your Preferred Candidate</CardTitle>
                <CardDescription>
                  Choose one candidate for the position of {election?.position || "Student Body President"}
                </CardDescription>
              </CardHeader>
              
              <CardContent className="p-6">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  {(election?.candidates || [])
                    .map((candidate) => (
                      <CandidateCard
                        key={candidate.id}
                        id={candidate.id}
                        name={candidate.name}
                        party={candidate.party}
                        position={candidate.position}
                        image={candidate.image}
                        onVote={handleVoteSelection}
                        isSelected={selectedCandidate === candidate.id}
                      />
                    ))}
                </div>
                
                <div className="mt-8 text-center">
                  <Button
                    onClick={handleProceedToStudentId}
                    disabled={!selectedCandidate || isVotingDisabled}
                    className="bg-gradient-to-r from-vote-primary to-vote-secondary hover:opacity-90 text-white transition-opacity duration-300 shadow-md"
                    size="lg"
                  >
                    <Vote className="mr-2 h-5 w-5" />
                    {isVotingDisabled
                      ? "Voting Closed"
                      : "Proceed to Verification"
                    }
                  </Button>
                  
                  {isVotingDisabled && (
                    <p className="mt-3 text-sm text-gray-500">
                      {hasReachedVoteLimit 
                        ? "This election has reached its maximum number of votes."
                        : "The voting period for this election has ended."
                      }
                    </p>
                  )}
                </div>
              </CardContent>
            </Card>
          )}
          
          {votingStep === "verify" && verificationFailed && (
            <Card className="border-0 shadow-lg overflow-hidden bg-gradient-to-br from-white to-vote-light">
              <CardHeader className="bg-white border-b">
                <div className="flex items-center">
                  <AlertCircle className="h-5 w-5 text-destructive mr-2" />
                  <div>
                    <CardTitle>Verification Failed</CardTitle>
                    <CardDescription>
                      Your biometric verification could not be confirmed
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              
              <CardContent className="p-8 text-center">
                <div className="mx-auto h-20 w-20 rounded-full bg-red-100 flex items-center justify-center mb-6">
                  <AlertCircle className="h-10 w-10 text-red-500" />
                </div>
                
                <h3 className="text-xl font-medium mb-3 text-gray-800">Unauthorized Access</h3>
                <p className="text-gray-600 mb-8">
                  Your fingerprint could not be verified. Only registered users with confirmed biometric data can vote in this election.
                </p>
                
                <div className="flex flex-col sm:flex-row justify-center gap-4">
                  <Button
                    variant="outline"
                    onClick={() => {
                      setVerificationFailed(false);
                      setVotingStep("select");
                    }}
                    className="border-vote-primary text-vote-primary hover:bg-vote-primary hover:text-white"
                  >
                    Return to Ballot
                  </Button>
                  
                  <Button
                    onClick={() => navigate("/")}
                    className="bg-vote-primary hover:bg-vote-secondary text-white"
                  >
                    Go to Home Page
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
          
          {votingStep === "verify" && !verificationFailed && !showBiometricModal && (
            <Card className="border-0 shadow-lg overflow-hidden bg-gradient-to-br from-white to-vote-light">
              <CardHeader className="bg-white border-b">
                <CardTitle>Biometric Verification Required</CardTitle>
                <CardDescription>
                  Please complete the biometric verification process
                </CardDescription>
              </CardHeader>
              
              <CardContent className="p-10 text-center">
                <div className="mx-auto h-24 w-24 rounded-full bg-vote-light flex items-center justify-center mb-6">
                  <Fingerprint className="h-12 w-12 text-vote-primary" />
                </div>
                
                <p className="text-gray-600 mb-6">
                  For security purposes, please verify your identity using your fingerprint.
                  This ensures that each person can only vote once.
                </p>
                
                <Button
                  onClick={() => setShowBiometricModal(true)}
                  className="bg-gradient-to-r from-vote-primary to-vote-secondary hover:opacity-90 text-white shadow-md"
                  size="lg"
                >
                  Start Biometric Verification
                </Button>
              </CardContent>
            </Card>
          )}
          
          {votingStep === "confirm" && selectedCandidateData && (
            <div className="relative z-10">
              <VoterConfirmation
                candidateId={selectedCandidate!}
                candidateData={selectedCandidateData}
                onConfirm={handleCastVote}
                onCancel={() => setVotingStep("select")}
                isLoading={isLoading}
              />
            </div>
          )}
        </div>
      </div>
      
      {/* Student ID Modal */}
      {showStudentIdModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="w-full max-w-md">
            <StudentIdVerification
              onVerified={handleStudentIdSuccess}
              onCancel={() => {
                setShowStudentIdModal(false);
                setVotingStep("select");
              }}
            />
          </div>
        </div>
      )}
      
      {/* Biometric Modal */}
      {showBiometricModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="w-full max-w-md">
            <BiometricVerification
              onVerified={handleBiometricSuccess}
              onCancel={() => {
                setShowBiometricModal(false);
                setVotingStep("studentId");
              }}
              userId={currentUser?.id}
            />
          </div>
        </div>
      )}
    </Layout>
  );
};

export default Voting;
