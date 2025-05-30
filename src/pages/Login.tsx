
import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import Layout from "@/components/Layout";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, Lock, CheckCircle2 } from "lucide-react";
import { toast } from "sonner";

const Login = () => {
  const [email, setEmail] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const { login, isLoading } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!email || !password) {
      toast.error("Please enter both email and password");
      return;
    }
    
    const success = await login(email, password);
    if (success) {
      navigate("/");
    }
  };

  return (
    <Layout>
      <div className="min-h-[80vh] flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8 bg-gray-50">
        <Card className="w-full max-w-md border-0 shadow-xl overflow-hidden bg-white">
          <CardHeader className="text-center bg-gradient-to-r from-vote-light to-white border-b pb-8">
            <div className="mx-auto mb-4 h-16 w-16 rounded-full bg-gradient-to-r from-vote-primary to-vote-secondary flex items-center justify-center">
              <CheckCircle2 className="h-8 w-8 text-white" />
            </div>
            <CardTitle className="text-2xl font-bold">Login to VoteGuard</CardTitle>
            <CardDescription>
              Access your account to participate in the election
            </CardDescription>
          </CardHeader>
          
          <form onSubmit={handleSubmit}>
            <CardContent className="space-y-4 pt-6">
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
                <div className="flex justify-between">
                  <label htmlFor="password" className="text-sm font-medium text-gray-700">
                    Password
                  </label>
                  <a href="#" className="text-sm font-medium text-vote-primary hover:text-vote-secondary">
                    Forgot password?
                  </a>
                </div>
                <div className="relative">
                  <Input
                    id="password"
                    type="password"
                    placeholder="••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="current-password"
                    className="w-full pr-10"
                  />
                  <Lock className="absolute right-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                </div>
              </div>
            </CardContent>
            
            <CardFooter className="flex flex-col space-y-4 border-t p-6 bg-gray-50">
              <Button
                type="submit"
                className="w-full bg-gradient-to-r from-vote-primary to-vote-secondary hover:opacity-90 text-white"
                disabled={isLoading}
              >
                {isLoading ? "Logging in..." : "Login"}
              </Button>
              
              <div className="text-sm text-center">
                Don't have an account?{" "}
                <Link to="/register" className="font-medium text-vote-primary hover:text-vote-secondary">
                  Register now
                </Link>
              </div>
            </CardFooter>
          </form>
          
          <div className="px-6 pb-6">
            <div className="border-t my-4"></div>
            <div className="text-xs text-gray-500 text-center">
              <p>Demo accounts:</p>
              <p className="mt-1">admin@university.edu / student@university.edu</p>
              <p className="mt-1">(any password will work)</p>
            </div>
          </div>
        </Card>
      </div>
    </Layout>
  );
};

export default Login;
