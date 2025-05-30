
import React, { createContext, useState, useContext, useEffect } from 'react';
import { toast } from 'sonner';

interface User {
  id: string;
  name: string;
  email: string;
  studentId: string;
  isAdmin: boolean;
  hasVoted: boolean;
  biometricVerified: boolean;
  fingerprintData?: string; // Store fingerprint data
}

interface AuthContextType {
  currentUser: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<boolean>;
  logout: () => void;
  register: (userData: Omit<User, 'id' | 'isAdmin' | 'hasVoted' | 'biometricVerified' | 'fingerprintData'> & { password: string }) => Promise<boolean>;
  verifyBiometric: () => Promise<boolean>;
  verifyStudentId: (id: string) => Promise<boolean>;
  setHasVoted: () => void;
  storeFingerprint: (fingerprintData: string) => Promise<boolean>;
  verifyFingerprint: (userId: string, fingerprintData: string) => Promise<boolean>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Mock users for demo
const mockUsers: User[] = [
  {
    id: '1',
    name: 'Admin User',
    email: 'admin@university.edu',
    studentId: 'A12345',
    isAdmin: true,
    hasVoted: false,
    biometricVerified: true,
    fingerprintData: 'mock-fingerprint-data-admin'
  },
  {
    id: '2',
    name: 'Student User',
    email: 'student@university.edu',
    studentId: 'S67890',
    isAdmin: false,
    hasVoted: false,
    biometricVerified: false,
    fingerprintData: 'mock-fingerprint-data-student'
  }
];

// For demo purposes, store users in memory
let registeredUsers = [...mockUsers];

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  
  useEffect(() => {
    // Check local storage for user
    const storedUser = localStorage.getItem('currentUser');
    if (storedUser) {
      setCurrentUser(JSON.parse(storedUser));
    }
    setIsLoading(false);
  }, []);

  const login = async (email: string, password: string): Promise<boolean> => {
    setIsLoading(true);
    
    // Simulate API call
    return new Promise((resolve) => {
      setTimeout(() => {
        const user = registeredUsers.find(user => user.email.toLowerCase() === email.toLowerCase());
        
        if (user) {
          setCurrentUser(user);
          localStorage.setItem('currentUser', JSON.stringify(user));
          toast.success(`Welcome back, ${user.name}!`);
          resolve(true);
        } else {
          toast.error('Invalid email or password');
          resolve(false);
        }
        
        setIsLoading(false);
      }, 1000);
    });
  };

  const logout = () => {
    setCurrentUser(null);
    localStorage.removeItem('currentUser');
    toast.success('Logged out successfully');
  };

  const register = async (userData: Omit<User, 'id' | 'isAdmin' | 'hasVoted' | 'biometricVerified' | 'fingerprintData'> & { password: string }): Promise<boolean> => {
    setIsLoading(true);
    
    // Simulate API call
    return new Promise((resolve) => {
      setTimeout(() => {
        const existingUser = registeredUsers.find(user => user.email.toLowerCase() === userData.email.toLowerCase());
        
        if (existingUser) {
          toast.error('Email already registered');
          setIsLoading(false);
          resolve(false);
          return;
        }
        
        const newUser: User = {
          id: `${registeredUsers.length + 1}`,
          ...userData,
          isAdmin: false,
          hasVoted: false,
          biometricVerified: true, // We set this to true because we've just registered biometrically
        };
        
        // In a real app, we would send this to a backend
        // For demo purposes, we'll just set it locally
        registeredUsers.push(newUser);
        setCurrentUser(newUser);
        localStorage.setItem('currentUser', JSON.stringify(newUser));
        toast.success('Registration successful!');
        setIsLoading(false);
        resolve(true);
      }, 1500);
    });
  };

  const verifyBiometric = async (): Promise<boolean> => {
    return new Promise((resolve) => {
      setTimeout(() => {
        if (currentUser) {
          const updatedUser = { ...currentUser, biometricVerified: true };
          setCurrentUser(updatedUser);
          localStorage.setItem('currentUser', JSON.stringify(updatedUser));
          
          // Update in the registered users array
          registeredUsers = registeredUsers.map(user => 
            user.id === currentUser.id ? updatedUser : user
          );
          
          toast.success('Biometric verification successful!');
          resolve(true);
        } else {
          toast.error('User not found');
          resolve(false);
        }
      }, 2000);
    });
  };

  const verifyStudentId = async (studentId: string): Promise<boolean> => {
    return new Promise((resolve) => {
      setTimeout(() => {
        if (currentUser) {
          // For demo purposes, accept if it matches the stored ID or with some probability
          const isValid = currentUser.studentId === studentId || Math.random() > 0.3;
          
          if (isValid) {
            toast.success('Student ID verified successfully!');
            resolve(true);
          } else {
            toast.error('Invalid Student ID');
            resolve(false);
          }
        } else {
          toast.error('User not found');
          resolve(false);
        }
      }, 1500);
    });
  };

  const storeFingerprint = async (fingerprintData: string): Promise<boolean> => {
    return new Promise((resolve) => {
      setTimeout(() => {
        if (currentUser) {
          const updatedUser = { 
            ...currentUser, 
            biometricVerified: true,
            fingerprintData
          };
          
          setCurrentUser(updatedUser);
          localStorage.setItem('currentUser', JSON.stringify(updatedUser));
          
          // Update in the registered users array
          registeredUsers = registeredUsers.map(user => 
            user.id === currentUser.id ? updatedUser : user
          );
          
          toast.success('Fingerprint registered successfully!');
          resolve(true);
        } else {
          toast.error('User not found');
          resolve(false);
        }
      }, 1500);
    });
  };

  const verifyFingerprint = async (userId: string, fingerprintData: string): Promise<boolean> => {
    return new Promise((resolve) => {
      setTimeout(() => {
        // Find user in the registered users array
        const user = registeredUsers.find(u => u.id === userId);
        
        if (user && user.fingerprintData) {
          // In a real app, we would do a proper comparison of fingerprint data
          // For demo purposes, we'll simulate verification after several attempts
          resolve(Math.random() > 0.3); // 70% success rate for demo
        } else {
          resolve(false);
        }
      }, 1500);
    });
  };

  const setHasVoted = () => {
    if (currentUser) {
      const updatedUser = { ...currentUser, hasVoted: true };
      setCurrentUser(updatedUser);
      localStorage.setItem('currentUser', JSON.stringify(updatedUser));
      
      // Update in the registered users array
      registeredUsers = registeredUsers.map(user => 
        user.id === currentUser.id ? updatedUser : user
      );
    }
  };

  return (
    <AuthContext.Provider
      value={{
        currentUser,
        isAuthenticated: !!currentUser,
        isLoading,
        login,
        logout,
        register,
        verifyBiometric,
        verifyStudentId,
        setHasVoted,
        storeFingerprint,
        verifyFingerprint
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
