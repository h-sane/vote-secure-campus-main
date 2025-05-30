
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import Layout from "@/components/Layout";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Share, Send } from "lucide-react";
import { toast } from "sonner";
import { useBlockchain } from "@/context/BlockchainContext";
import { useAuth } from "@/context/AuthContext";

const CreateVote = () => {
  const navigate = useNavigate();
  const { createElection, isLoading } = useBlockchain();
  const { currentUser, isAuthenticated } = useAuth();
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [position, setPosition] = useState("Student Body President");
  const [candidates, setCandidates] = useState([
    { name: "", party: "", image: "/placeholder.svg" },
    { name: "", party: "", image: "/placeholder.svg" },
  ]);
  const [showShareModal, setShowShareModal] = useState(false);
  const [electionId, setElectionId] = useState<string | null>(null);

  // Check if user is authenticated
  React.useEffect(() => {
    if (!isAuthenticated) {
      toast.error("You must be logged in to create a vote");
      navigate("/login");
    }
  }, [isAuthenticated, navigate]);

  const handleAddCandidate = () => {
    setCandidates([...candidates, { name: "", party: "", image: "/placeholder.svg" }]);
  };

  const handleCandidateChange = (index: number, field: "name" | "party" | "image", value: string) => {
    const updatedCandidates = [...candidates];
    updatedCandidates[index][field] = value;
    setCandidates(updatedCandidates);
  };

  const handleRemoveCandidate = (index: number) => {
    if (candidates.length <= 2) {
      toast.error("At least two candidates are required");
      return;
    }
    const updatedCandidates = candidates.filter((_, i) => i !== index);
    setCandidates(updatedCandidates);
  };

  const handleCreateVote = async () => {
    // Validation
    if (!title.trim()) {
      toast.error("Please enter a title for the election");
      return;
    }

    if (!position.trim()) {
      toast.error("Please enter a position for the candidates");
      return;
    }

    const invalidCandidates = candidates.filter(candidate => !candidate.name.trim() || !candidate.party.trim());
    if (invalidCandidates.length > 0) {
      toast.error("Please fill in all candidate details");
      return;
    }

    if (!currentUser) return;
    
    // Create election
    try {
      const election = {
        title,
        description,
        position,
        createdBy: currentUser.id,
        candidates: candidates.map(candidate => ({
          name: candidate.name,
          party: candidate.party,
          position,
          image: candidate.image,
        })),
      };
      
      const newElectionId = await createElection(election);
      
      if (newElectionId) {
        setElectionId(newElectionId);
        setShowShareModal(true);
        toast.success("Election created successfully!");
      }
    } catch (error) {
      console.error("Error creating election:", error);
      toast.error("Failed to create election");
    }
  };

  const handleCopyLink = () => {
    if (!electionId) return;
    
    const voteUrl = `${window.location.origin}/voting/${electionId}`;
    navigator.clipboard.writeText(voteUrl);
    toast.success("Vote link copied to clipboard!");
  };

  return (
    <Layout>
      <div className="container mx-auto px-4 py-12">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-3xl font-bold text-vote-dark mb-8">Create Election</h1>
          
          <Card>
            <CardHeader>
              <CardTitle>Election Details</CardTitle>
              <CardDescription>
                Create a new election for students to vote on
              </CardDescription>
            </CardHeader>
            
            <CardContent className="space-y-6">
              {/* Election basics */}
              <div className="space-y-4">
                <div>
                  <Label htmlFor="title">Election Title</Label>
                  <Input 
                    id="title" 
                    value={title} 
                    onChange={(e) => setTitle(e.target.value)}
                    placeholder="Spring 2025 Student Government Election"
                  />
                </div>
                
                <div>
                  <Label htmlFor="description">Description (Optional)</Label>
                  <Textarea 
                    id="description" 
                    value={description} 
                    onChange={(e) => setDescription(e.target.value)}
                    placeholder="Elect your representatives for the upcoming academic year..."
                    rows={3}
                  />
                </div>
                
                <div>
                  <Label htmlFor="position">Position</Label>
                  <Input 
                    id="position" 
                    value={position} 
                    onChange={(e) => setPosition(e.target.value)}
                    placeholder="Student Body President"
                  />
                </div>
              </div>
              
              {/* Candidates */}
              <div>
                <div className="flex justify-between items-center mb-4">
                  <h3 className="font-semibold text-lg">Candidates</h3>
                  <Button 
                    variant="outline" 
                    size="sm"
                    onClick={handleAddCandidate}
                    className="text-vote-primary border-vote-primary hover:bg-vote-primary hover:text-white"
                  >
                    Add Candidate
                  </Button>
                </div>
                
                <div className="space-y-6">
                  {candidates.map((candidate, index) => (
                    <div key={index} className="p-4 border rounded-md bg-slate-50">
                      <div className="flex justify-between items-center mb-3">
                        <h4 className="font-medium">Candidate {index + 1}</h4>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleRemoveCandidate(index)}
                          className="text-red-500 hover:bg-red-50"
                        >
                          Remove
                        </Button>
                      </div>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <Label htmlFor={`candidate-${index}-name`}>Name</Label>
                          <Input
                            id={`candidate-${index}-name`}
                            value={candidate.name}
                            onChange={(e) => handleCandidateChange(index, "name", e.target.value)}
                            placeholder="Candidate name"
                          />
                        </div>
                        
                        <div>
                          <Label htmlFor={`candidate-${index}-party`}>Party/Affiliation</Label>
                          <Input
                            id={`candidate-${index}-party`}
                            value={candidate.party}
                            onChange={(e) => handleCandidateChange(index, "party", e.target.value)}
                            placeholder="Party or affiliation"
                          />
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
            
            <CardFooter>
              <Button
                onClick={handleCreateVote}
                disabled={isLoading}
                className="bg-vote-primary hover:bg-vote-secondary text-white"
              >
                <Send className="mr-2 h-4 w-4" />
                {isLoading ? "Creating..." : "Create Election"}
              </Button>
            </CardFooter>
          </Card>
        </div>
      </div>

      {/* Share Modal */}
      {showShareModal && electionId && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="w-full max-w-md">
            <Card>
              <CardHeader>
                <CardTitle>Share Your Election</CardTitle>
                <CardDescription>
                  Share this link with voters to allow them to cast their votes
                </CardDescription>
              </CardHeader>
              
              <CardContent>
                <div className="bg-vote-light p-4 rounded-md mb-4">
                  <p className="text-sm font-mono break-all">
                    {`${window.location.origin}/voting/${electionId}`}
                  </p>
                </div>
              </CardContent>
              
              <CardFooter className="flex justify-between">
                <Button
                  variant="outline"
                  onClick={() => {
                    setShowShareModal(false);
                    navigate(`/voting/${electionId}`);
                  }}
                >
                  Go to Voting Page
                </Button>
                
                <Button 
                  onClick={handleCopyLink}
                  className="bg-vote-primary hover:bg-vote-secondary text-white"
                >
                  <Share className="mr-2 h-4 w-4" />
                  Copy Link
                </Button>
              </CardFooter>
            </Card>
          </div>
        </div>
      )}
    </Layout>
  );
};

export default CreateVote;
