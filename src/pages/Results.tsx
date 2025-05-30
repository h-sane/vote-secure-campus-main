
import React, { useEffect } from "react";
import { useParams } from "react-router-dom";
import Layout from "@/components/Layout";
import ResultsChart from "@/components/ResultsChart";
import BlockchainExplorer from "@/components/BlockchainExplorer";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useBlockchain } from "@/context/BlockchainContext";
import { toast } from "sonner";
import { BarChart3, Shield, Lock } from "lucide-react";

const Results = () => {
  const { getResults, getElection, setCurrentElection } = useBlockchain();
  const { electionId } = useParams<{ electionId?: string }>();
  
  useEffect(() => {
    if (electionId) {
      const election = getElection(electionId);
      if (election) {
        setCurrentElection(electionId);
      } else {
        toast.error("Election not found");
      }
    }
  }, [electionId, getElection, setCurrentElection]);
  
  const results = getResults(electionId);
  const election = electionId ? getElection(electionId) : undefined;

  return (
    <Layout>
      <div className="container mx-auto px-4 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center mb-6">
            <div className="h-10 w-10 rounded-full bg-gradient-to-r from-vote-primary to-vote-secondary flex items-center justify-center mr-3">
              <BarChart3 className="h-5 w-5 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-vote-dark">
                {election ? election.title : "Election Results"}
              </h1>
              {election?.description && (
                <p className="text-gray-600">{election.description}</p>
              )}
            </div>
          </div>
          
          <div className="flex items-center mb-8 p-3 rounded-lg bg-vote-light border border-vote-accent">
            <Lock className="h-5 w-5 text-vote-primary mr-2" />
            <span className="text-sm text-gray-700">Results are securely stored on the blockchain and cannot be tampered with</span>
          </div>
          
          <Tabs defaultValue="results" className="w-full">
            <TabsList className="mb-6 bg-gradient-to-r from-vote-primary/10 to-vote-secondary/10 p-1 rounded-lg">
              <TabsTrigger value="results" className="data-[state=active]:bg-white">Results</TabsTrigger>
              <TabsTrigger value="blockchain" className="data-[state=active]:bg-white">Blockchain Explorer</TabsTrigger>
            </TabsList>
            
            <TabsContent value="results">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <Card className="border-0 shadow-lg overflow-hidden bg-gradient-to-br from-white to-vote-light">
                  <CardHeader className="bg-white border-b">
                    <CardTitle>Vote Distribution</CardTitle>
                    <CardDescription>
                      Visual representation of votes received by each candidate
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="p-6">
                    <ResultsChart candidates={results} />
                  </CardContent>
                </Card>
                
                <Card className="border-0 shadow-lg overflow-hidden bg-gradient-to-br from-white to-vote-light">
                  <CardHeader className="bg-white border-b">
                    <CardTitle>Candidate Rankings</CardTitle>
                    <CardDescription>
                      Candidates ranked by number of votes received
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="p-6">
                    <div className="space-y-4">
                      {results.map((candidate, index) => (
                        <div key={candidate.id} className="flex items-center transform transition-transform hover:scale-102 hover:bg-vote-light p-3 rounded-md">
                          <div className={`w-10 h-10 rounded-full flex items-center justify-center mr-4 ${
                            index === 0 ? "bg-gradient-to-r from-yellow-400 to-yellow-200 text-yellow-800 border-2 border-yellow-400" :
                            index === 1 ? "bg-gradient-to-r from-gray-400 to-gray-200 text-gray-800 border-2 border-gray-400" :
                            index === 2 ? "bg-gradient-to-r from-amber-600 to-amber-300 text-amber-800 border-2 border-amber-400" :
                            "bg-vote-light text-gray-800"
                          }`}>
                            {index + 1}
                          </div>
                          
                          <div className="flex-1 min-w-0">
                            <div className="flex justify-between items-center mb-1">
                              <p className="font-medium truncate">{candidate.name}</p>
                              <span className="font-bold text-vote-primary bg-vote-light px-2 py-1 rounded-full text-sm">
                                {candidate.votes} votes
                              </span>
                            </div>
                            
                            <div className="w-full bg-gray-200 rounded-full h-2.5 overflow-hidden">
                              <div 
                                className="bg-gradient-to-r from-vote-primary to-vote-secondary h-2.5 rounded-full" 
                                style={{ 
                                  width: `${results[0].votes > 0 ? (candidate.votes / results[0].votes) * 100 : 0}%` 
                                }}
                              ></div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
            
            <TabsContent value="blockchain">
              <Card className="border-0 shadow-lg overflow-hidden bg-gradient-to-br from-white to-vote-light">
                <CardHeader className="bg-white border-b">
                  <div className="flex items-center">
                    <Shield className="h-5 w-5 text-vote-primary mr-2" />
                    <div>
                      <CardTitle>Blockchain Explorer</CardTitle>
                      <CardDescription>
                        Explore the immutable record of all votes in the blockchain
                      </CardDescription>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="p-6">
                  <BlockchainExplorer />
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </Layout>
  );
};

export default Results;
