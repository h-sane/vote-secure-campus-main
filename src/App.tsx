
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { useEffect } from "react";
import Index from "./pages/Index";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Voting from "./pages/Voting";
import Results from "./pages/Results";
import Admin from "./pages/Admin";
import NotFound from "./pages/NotFound";
import CreateVote from "./pages/CreateVote";
import { BlockchainProvider } from "./context/BlockchainContext";
import { AuthProvider } from "./context/AuthContext";

const queryClient = new QueryClient();

const App = () => {
  // Set the application title
  useEffect(() => {
    document.title = "VoteGuard - Secure Blockchain Voting";
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BlockchainProvider>
          <TooltipProvider>
            <Toaster />
            <Sonner />
            <BrowserRouter>
              <Routes>
                <Route path="/" element={<Index />} />
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                <Route path="/voting" element={<Voting />} />
                <Route path="/voting/:electionId" element={<Voting />} />
                <Route path="/results" element={<Results />} />
                <Route path="/results/:electionId" element={<Results />} />
                <Route path="/admin" element={<Admin />} />
                <Route path="/create-vote" element={<CreateVote />} />
                <Route path="*" element={<NotFound />} />
              </Routes>
            </BrowserRouter>
          </TooltipProvider>
        </BlockchainProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
};

export default App;
