
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { Button } from "@/components/ui/button";
import { Shield, User, Vote, CheckCircle2 } from "lucide-react";

interface LayoutProps {
  children: React.ReactNode;
  showNav?: boolean;
}

const Layout = ({ children, showNav = true }: LayoutProps) => {
  const navigate = useNavigate();
  const { isAuthenticated, currentUser, logout } = useAuth();

  return (
    <div className="min-h-screen flex flex-col bg-gray-50">
      {showNav && (
        <header className="bg-white shadow-md border-b border-gray-100">
          <div className="container mx-auto px-4 py-4 flex justify-between items-center">
            <div 
              className="flex items-center space-x-2 cursor-pointer" 
              onClick={() => navigate("/")}
            >
              <div className="h-10 w-10 rounded-full bg-gradient-to-br from-vote-primary to-vote-secondary flex items-center justify-center">
                <CheckCircle2 className="h-6 w-6 text-white" />
              </div>
              <span className="text-2xl font-bold bg-gradient-to-r from-vote-primary to-vote-secondary bg-clip-text text-transparent">
                VoteGuard
              </span>
            </div>

            <nav className="hidden md:flex items-center space-x-8">
              <Button
                variant="ghost"
                onClick={() => navigate("/")}
                className="text-gray-700 hover:text-vote-primary hover:bg-vote-light"
              >
                Home
              </Button>
              
              {isAuthenticated && !currentUser?.hasVoted && (
                <Button
                  variant="ghost"
                  onClick={() => navigate("/voting")}
                  className="text-gray-700 hover:text-vote-primary hover:bg-vote-light"
                >
                  Vote
                </Button>
              )}
              
              <Button
                variant="ghost"
                onClick={() => navigate("/results")}
                className="text-gray-700 hover:text-vote-primary hover:bg-vote-light"
              >
                Results
              </Button>
              
              {isAuthenticated && currentUser?.isAdmin && (
                <Button
                  variant="ghost"
                  onClick={() => navigate("/admin")}
                  className="text-gray-700 hover:text-vote-primary hover:bg-vote-light"
                >
                  Admin
                </Button>
              )}
            </nav>

            <div className="flex items-center space-x-4">
              {isAuthenticated ? (
                <div className="flex items-center space-x-4">
                  <div className="hidden md:flex items-center space-x-2 bg-vote-light px-3 py-1.5 rounded-full">
                    <User className="h-4 w-4 text-vote-primary" />
                    <span className="text-sm font-medium">{currentUser?.name}</span>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      logout();
                      navigate("/");
                    }}
                    className="border-vote-primary text-vote-primary hover:bg-vote-primary hover:text-white transition-colors duration-300"
                  >
                    Logout
                  </Button>
                </div>
              ) : (
                <div className="flex items-center space-x-3">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => navigate("/login")}
                    className="border-vote-primary text-vote-primary hover:bg-vote-primary hover:text-white transition-colors duration-300"
                  >
                    Login
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => navigate("/register")}
                    className="bg-gradient-to-r from-vote-primary to-vote-secondary hover:opacity-90 text-white transition-opacity duration-300"
                  >
                    Register
                  </Button>
                </div>
              )}
            </div>
          </div>
        </header>
      )}

      <main className="flex-grow">{children}</main>

      <footer className="bg-gradient-to-r from-vote-dark to-[#2D2351] text-white py-6">
        <div className="container mx-auto px-4">
          <div className="flex flex-col md:flex-row justify-between items-center">
            <div className="flex items-center space-x-2 mb-4 md:mb-0">
              <Vote className="h-6 w-6 text-vote-accent" />
              <span className="text-xl font-bold">VoteGuard</span>
            </div>
            <div className="text-sm text-gray-400">
              © {new Date().getFullYear()} VoteGuard. All rights reserved.
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Layout;
