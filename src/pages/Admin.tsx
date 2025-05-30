
import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import Layout from "@/components/Layout";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useAuth } from "@/context/AuthContext";
import { useBlockchain } from "@/context/BlockchainContext";
import { toast } from "sonner";

const Admin = () => {
  const { currentUser, isAuthenticated } = useAuth();
  const { addCandidate, candidates, blockchain } = useBlockchain();
  const navigate = useNavigate();
  
  const [newCandidate, setNewCandidate] = useState({
    name: "",
    party: "",
    position: "Student Body President",
    image: "/placeholder.svg"
  });
  
  // Redirect non-admin users
  useEffect(() => {
    if (!isAuthenticated || (currentUser && !currentUser.isAdmin)) {
      toast.error("You don't have permission to access this page");
      navigate("/");
    }
  }, [isAuthenticated, currentUser, navigate]);
  
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setNewCandidate(prev => ({
      ...prev,
      [name]: value
    }));
  };
  
  const handleAddCandidate = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!newCandidate.name || !newCandidate.party || !newCandidate.position) {
      toast.error("Please fill out all fields");
      return;
    }
    
    const success = await addCandidate(newCandidate);
    
    if (success) {
      setNewCandidate({
        name: "",
        party: "",
        position: "Student Body President",
        image: "/placeholder.svg"
      });
    }
  };

  return (
    <Layout>
      <div className="container mx-auto px-4 py-12">
        <h1 className="text-3xl font-bold mb-8 text-vote-dark">Admin Dashboard</h1>
        
        <Tabs defaultValue="candidates">
          <TabsList className="grid w-full grid-cols-3 max-w-md mb-8">
            <TabsTrigger value="candidates">Candidates</TabsTrigger>
            <TabsTrigger value="voters">Voters</TabsTrigger>
            <TabsTrigger value="system">System</TabsTrigger>
          </TabsList>
          
          {/* Candidates Tab */}
          <TabsContent value="candidates">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              <Card className="lg:col-span-2">
                <CardHeader>
                  <CardTitle>Manage Candidates</CardTitle>
                  <CardDescription>
                    View and manage candidates for the election
                  </CardDescription>
                </CardHeader>
                
                <CardContent>
                  <div className="rounded-md border overflow-x-auto">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-[50px]">ID</TableHead>
                          <TableHead>Name</TableHead>
                          <TableHead>Party</TableHead>
                          <TableHead>Position</TableHead>
                          <TableHead className="text-right">Votes</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {candidates.map((candidate) => (
                          <TableRow key={candidate.id}>
                            <TableCell className="font-medium">{candidate.id}</TableCell>
                            <TableCell>{candidate.name}</TableCell>
                            <TableCell>{candidate.party}</TableCell>
                            <TableCell>{candidate.position}</TableCell>
                            <TableCell className="text-right">{candidate.votes}</TableCell>
                          </TableRow>
                        ))}
                        
                        {candidates.length === 0 && (
                          <TableRow>
                            <TableCell colSpan={5} className="text-center py-6 text-gray-500">
                              No candidates found
                            </TableCell>
                          </TableRow>
                        )}
                      </TableBody>
                    </Table>
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardHeader>
                  <CardTitle>Add New Candidate</CardTitle>
                  <CardDescription>
                    Add a new candidate to the election
                  </CardDescription>
                </CardHeader>
                
                <CardContent>
                  <form onSubmit={handleAddCandidate}>
                    <div className="space-y-4">
                      <div className="space-y-2">
                        <Label htmlFor="name">Full Name</Label>
                        <Input
                          id="name"
                          name="name"
                          placeholder="Jane Doe"
                          value={newCandidate.name}
                          onChange={handleInputChange}
                          required
                        />
                      </div>
                      
                      <div className="space-y-2">
                        <Label htmlFor="party">Party/Coalition</Label>
                        <Input
                          id="party"
                          name="party"
                          placeholder="Student Unity Party"
                          value={newCandidate.party}
                          onChange={handleInputChange}
                          required
                        />
                      </div>
                      
                      <div className="space-y-2">
                        <Label htmlFor="position">Position</Label>
                        <Input
                          id="position"
                          name="position"
                          placeholder="Student Body President"
                          value={newCandidate.position}
                          onChange={handleInputChange}
                          required
                        />
                      </div>
                      
                      <div className="space-y-2">
                        <Label htmlFor="image">Image URL (optional)</Label>
                        <Input
                          id="image"
                          name="image"
                          placeholder="/placeholder.svg"
                          value={newCandidate.image}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                    
                    <Button type="submit" className="w-full mt-6 bg-vote-primary hover:bg-vote-secondary text-white">
                      Add Candidate
                    </Button>
                  </form>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
          
          {/* Voters Tab */}
          <TabsContent value="voters">
            <Card>
              <CardHeader>
                <CardTitle>Registered Voters</CardTitle>
                <CardDescription>
                  Manage voter registrations and verify eligibility
                </CardDescription>
              </CardHeader>
              
              <CardContent>
                <div className="text-center py-12 text-gray-500">
                  Voter management functionality coming soon...
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          {/* System Tab */}
          <TabsContent value="system">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <Card>
                <CardHeader>
                  <CardTitle>System Statistics</CardTitle>
                  <CardDescription>
                    Overview of election system performance
                  </CardDescription>
                </CardHeader>
                
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex justify-between p-4 bg-gray-50 rounded-lg">
                      <span className="font-medium text-gray-600">Total Candidates</span>
                      <span className="font-bold text-vote-primary">{candidates.length}</span>
                    </div>
                    
                    <div className="flex justify-between p-4 bg-gray-50 rounded-lg">
                      <span className="font-medium text-gray-600">Total Votes Cast</span>
                      <span className="font-bold text-vote-primary">
                        {blockchain.filter(block => block.voter !== 'GENESIS').length}
                      </span>
                    </div>
                    
                    <div className="flex justify-between p-4 bg-gray-50 rounded-lg">
                      <span className="font-medium text-gray-600">Blockchain Size</span>
                      <span className="font-bold text-vote-primary">{blockchain.length} blocks</span>
                    </div>
                    
                    <div className="flex justify-between p-4 bg-gray-50 rounded-lg">
                      <span className="font-medium text-gray-600">System Status</span>
                      <span className="text-green-500 font-medium">Active</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardHeader>
                  <CardTitle>Election Controls</CardTitle>
                  <CardDescription>
                    Manage election settings and status
                  </CardDescription>
                </CardHeader>
                
                <CardContent className="space-y-6">
                  <div className="flex items-center justify-between p-4 border rounded-lg">
                    <div>
                      <h3 className="font-medium">Election Status</h3>
                      <p className="text-sm text-gray-500">Current election is active</p>
                    </div>
                    <div>
                      <Button variant="outline" className="border-vote-primary text-vote-primary hover:bg-vote-primary hover:text-white">
                        End Election
                      </Button>
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between p-4 border rounded-lg">
                    <div>
                      <h3 className="font-medium">Reset System</h3>
                      <p className="text-sm text-gray-500">Clear all data and start fresh</p>
                    </div>
                    <div>
                      <Button variant="destructive">Reset</Button>
                    </div>
                  </div>
                </CardContent>
                
                <CardFooter className="border-t pt-6">
                  <p className="text-sm text-gray-500 italic w-full">
                    Note: These actions cannot be undone and will affect all users in the system
                  </p>
                </CardFooter>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </Layout>
  );
};

export default Admin;
