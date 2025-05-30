import { useNavigate } from "react-router-dom";
import Layout from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Shield, Vote, Fingerprint, Lock, CheckCircle2, ClipboardList } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { useBlockchain } from "@/context/BlockchainContext";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import ResultsChart from "@/components/ResultsChart";

const Index = () => {
  const navigate = useNavigate();
  const { isAuthenticated, currentUser } = useAuth();
  const { getAllElections, getResults } = useBlockchain();

  // Empty elections by default for development
  const recentElections = [];
  const hasActiveElections = false;
  // We're not showing any featured election during development
  const featuredElection = null;
  const featuredResults = [];

  return (
    <Layout>
      {/* Hero Section */}
      <section className="pt-16 md:pt-24 pb-12 bg-gradient-to-br from-vote-light via-white to-vote-light">
        <div className="container mx-auto px-4 text-center">
          <div className="mb-6 mx-auto h-16 w-16 rounded-full bg-gradient-to-br from-vote-primary to-vote-secondary flex items-center justify-center">
            <CheckCircle2 className="h-8 w-8 text-white" />
          </div>
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6 bg-gradient-to-r from-vote-primary to-vote-secondary bg-clip-text text-transparent">
            Secure. Transparent. Verifiable.
          </h1>
          <p className="text-lg md:text-xl text-gray-700 max-w-3xl mx-auto mb-12">
            Welcome to VoteGuard, the secure digital voting platform for your college elections.
            Powered by blockchain technology and biometric authentication.
          </p>
          
          <div className="flex flex-col sm:flex-row justify-center gap-4 mb-6">
            {isAuthenticated ? (
              <>
                {!currentUser?.hasVoted ? (
                  <Button 
                    size="lg" 
                    onClick={() => navigate("/voting")}
                    className="bg-gradient-to-r from-vote-primary to-vote-secondary hover:opacity-90 text-white transition-opacity duration-300 shadow-lg"
                  >
                    <Vote className="mr-2 h-5 w-5" />
                    Cast Your Vote
                  </Button>
                ) : (
                  <Button 
                    size="lg" 
                    onClick={() => navigate("/results")}
                    className="bg-gradient-to-r from-vote-primary to-vote-secondary hover:opacity-90 text-white transition-opacity duration-300 shadow-lg"
                  >
                    View Election Results
                  </Button>
                )}
              </>
            ) : (
              <>
                <Button 
                  size="lg" 
                  onClick={() => navigate("/register")}
                  className="bg-gradient-to-r from-vote-primary to-vote-secondary hover:opacity-90 text-white transition-opacity duration-300 shadow-lg"
                >
                  Register Now
                </Button>
                <Button 
                  size="lg" 
                  variant="outline" 
                  onClick={() => navigate("/login")}
                  className="border-vote-primary text-vote-primary hover:bg-vote-primary hover:text-white transition-colors duration-300"
                >
                  Login
                </Button>
              </>
            )}
          </div>
          
          {isAuthenticated && (
            <div className="mb-12">
              <Button 
                size="lg" 
                variant="outline" 
                onClick={() => navigate("/create-vote")}
                className="border-vote-primary text-vote-primary hover:bg-vote-primary hover:text-white transition-colors duration-300"
              >
                <ClipboardList className="mr-2 h-5 w-5" />
                Create Your Own Election
              </Button>
            </div>
          )}
        </div>
      </section>

      {/* Live Results Section */}
      <section className="py-12 bg-white">
        <div className="container mx-auto px-4">
          <h2 className="text-3xl font-bold mb-8 text-center">
            {hasActiveElections ? "Live Election Results" : "No Active Elections"}
          </h2>
          
          {/* Always show "No Active Elections" during development */}
          <div className="max-w-2xl mx-auto text-center bg-vote-light p-8 rounded-xl shadow-sm">
            <div className="text-6xl text-vote-primary mb-4">📊</div>
            <h3 className="text-xl font-medium mb-2">No active elections at the moment</h3>
            <p className="text-gray-600 mb-6">
              When elections are created, they will appear here with live results and statistics.
            </p>
            {isAuthenticated && (
              <Button 
                onClick={() => navigate("/create-vote")} 
                className="bg-gradient-to-r from-vote-primary to-vote-secondary hover:opacity-90 text-white"
              >
                <ClipboardList className="mr-2 h-4 w-4" />
                Create an Election
              </Button>
            )}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-16 bg-gradient-to-br from-vote-light to-white">
        <div className="container mx-auto px-4">
          <h2 className="text-3xl md:text-4xl font-bold mb-12 text-center">
            How It Works
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="bg-white p-8 rounded-xl shadow-md text-center transform transition-transform hover:scale-105">
              <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-gradient-to-br from-vote-primary to-vote-secondary bg-opacity-10 mb-6">
                <Fingerprint className="h-8 w-8 text-vote-primary" />
              </div>
              <h3 className="text-xl font-bold mb-3 text-vote-dark">Biometric Verification</h3>
              <p className="text-gray-600">
                Secure authentication using fingerprint technology ensures that only eligible students can vote, and each student votes only once.
              </p>
            </div>
            
            <div className="bg-white p-8 rounded-xl shadow-md text-center transform transition-transform hover:scale-105">
              <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-gradient-to-br from-vote-primary to-vote-secondary bg-opacity-10 mb-6">
                <Lock className="h-8 w-8 text-vote-primary" />
              </div>
              <h3 className="text-xl font-bold mb-3 text-vote-dark">Blockchain Powered</h3>
              <p className="text-gray-600">
                Every vote is recorded on an immutable blockchain, ensuring vote integrity and creating a transparent, tamper-proof record of the election.
              </p>
            </div>
            
            <div className="bg-white p-8 rounded-xl shadow-md text-center transform transition-transform hover:scale-105">
              <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-gradient-to-br from-vote-primary to-vote-secondary bg-opacity-10 mb-6">
                <Shield className="h-8 w-8 text-vote-primary" />
              </div>
              <h3 className="text-xl font-bold mb-3 text-vote-dark">Total Transparency</h3>
              <p className="text-gray-600">
                Real-time results are publicly available, and the entire voting process can be audited through our blockchain explorer.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-16 bg-gradient-to-r from-vote-dark to-[#2D2351] text-white">
        <div className="container mx-auto px-4 text-center">
          <h2 className="text-3xl md:text-4xl font-bold mb-6">
            Ready to Transform Campus Elections?
          </h2>
          <p className="text-lg text-gray-300 max-w-2xl mx-auto mb-8">
            Join the digital voting revolution and experience the most secure, transparent, and efficient election process.
          </p>
          <div className="flex flex-wrap justify-center gap-4">
            <Button 
              size="lg" 
              onClick={() => navigate(isAuthenticated ? "/voting" : "/register")}
              className="bg-white text-vote-primary hover:bg-vote-light transition-colors"
            >
              {isAuthenticated ? "Go to Voting" : "Get Started Now"}
            </Button>
            {isAuthenticated && (
              <Button 
                size="lg" 
                variant="outline" 
                onClick={() => navigate("/create-vote")}
                className="border-white text-white hover:bg-white hover:text-vote-dark"
              >
                Create Election
              </Button>
            )}
          </div>
        </div>
      </section>
    </Layout>
  );
};

export default Index;
