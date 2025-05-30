import React, { createContext, useState, useContext, useEffect } from 'react';
import { toast } from 'sonner';

interface Candidate {
  id: string;
  name: string;
  party: string;
  position: string;
  image: string;
  votes: number;
}

interface Election {
  id: string;
  title: string;
  description: string;
  position: string;
  createdBy: string;
  createdAt: number;
  candidates: Candidate[];
  voteLimit?: number;
  endTime?: string;
}

interface Block {
  id: string;
  timestamp: number;
  voter: string;
  candidate: string;
  election: string;
  previousHash: string;
  hash: string;
}

interface ElectionInput {
  title: string;
  description: string;
  position: string;
  createdBy: string;
  candidates: Omit<Candidate, 'id' | 'votes'>[];
  voteLimit?: number;
  endTime?: string;
}

interface BlockchainContextType {
  candidates: Candidate[];
  blockchain: Block[];
  elections: Election[];
  isLoading: boolean;
  castVote: (candidateId: string, voterId: string, electionId?: string) => Promise<boolean>;
  getResults: (electionId?: string) => Candidate[];
  addCandidate: (candidate: Omit<Candidate, 'id' | 'votes'>) => Promise<boolean>;
  createElection: (election: ElectionInput) => Promise<string>;
  getElection: (electionId: string) => Election | undefined;
  getCurrentElection: () => Election | undefined;
  setCurrentElection: (electionId: string) => void;
  getAllElections: () => Election[];
}

const BlockchainContext = createContext<BlockchainContextType | undefined>(undefined);

// Mock candidates for demo
const initialCandidates: Candidate[] = [
  {
    id: '1',
    name: 'Alex Johnson',
    party: 'Student Progress Party',
    position: 'Student Body President',
    image: '/placeholder.svg',
    votes: 42
  },
  {
    id: '2',
    name: 'Maria Rodriguez',
    party: 'Campus Forward Coalition',
    position: 'Student Body President',
    image: '/placeholder.svg',
    votes: 36
  },
  {
    id: '3',
    name: 'David Lee',
    party: 'Academic Excellence Union',
    position: 'Student Body President',
    image: '/placeholder.svg',
    votes: 28
  }
];

// Initial election
const initialElections: Election[] = [
  {
    id: 'default',
    title: 'Student Government Election 2025',
    description: 'Vote for your Student Body President',
    position: 'Student Body President',
    createdBy: 'admin',
    createdAt: Date.now() - 86400000,
    candidates: initialCandidates
  }
];

// Mock blockchain for demo
const initialBlockchain: Block[] = [
  {
    id: '0',
    timestamp: Date.now() - 86400000,
    voter: 'GENESIS',
    candidate: 'GENESIS',
    election: 'GENESIS',
    previousHash: '0',
    hash: '000000'
  }
];

// Simple hash function for demo
const hashBlock = (block: Omit<Block, 'hash'>): string => {
  const blockString = JSON.stringify(block);
  let hash = 0;
  for (let i = 0; i < blockString.length; i++) {
    const char = blockString.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }
  return hash.toString(16).padStart(8, '0');
};

export const BlockchainProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [candidates, setCandidates] = useState<Candidate[]>(initialCandidates);
  const [blockchain, setBlockchain] = useState<Block[]>(initialBlockchain);
  const [elections, setElections] = useState<Election[]>(initialElections);
  const [currentElectionId, setCurrentElectionId] = useState<string>('default');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  
  useEffect(() => {
    // Load from localStorage if available
    const storedCandidates = localStorage.getItem('candidates');
    const storedBlockchain = localStorage.getItem('blockchain');
    const storedElections = localStorage.getItem('elections');
    const storedCurrentElection = localStorage.getItem('currentElection');
    
    if (storedCandidates) {
      setCandidates(JSON.parse(storedCandidates));
    }
    
    if (storedBlockchain) {
      setBlockchain(JSON.parse(storedBlockchain));
    }
    
    if (storedElections) {
      setElections(JSON.parse(storedElections));
    }
    
    if (storedCurrentElection) {
      setCurrentElectionId(storedCurrentElection);
    }
  }, []);
  
  // Save to localStorage when state changes
  useEffect(() => {
    localStorage.setItem('candidates', JSON.stringify(candidates));
  }, [candidates]);
  
  useEffect(() => {
    localStorage.setItem('blockchain', JSON.stringify(blockchain));
  }, [blockchain]);
  
  useEffect(() => {
    localStorage.setItem('elections', JSON.stringify(elections));
  }, [elections]);
  
  useEffect(() => {
    localStorage.setItem('currentElection', currentElectionId);
  }, [currentElectionId]);

  const getAllElections = (): Election[] => {
    return [...elections];
  };

  const getCurrentElection = (): Election | undefined => {
    return elections.find(e => e.id === currentElectionId);
  };

  const getElection = (electionId: string): Election | undefined => {
    return elections.find(e => e.id === electionId);
  };

  const setCurrentElection = (electionId: string) => {
    const election = elections.find(e => e.id === electionId);
    if (election) {
      setCurrentElectionId(electionId);
    } else {
      toast.error('Election not found');
    }
  };

  const createElection = async (electionInput: ElectionInput): Promise<string> => {
    setIsLoading(true);
    
    return new Promise((resolve) => {
      setTimeout(() => {
        try {
          const electionId = `election-${Date.now().toString(36)}-${Math.random().toString(36).substr(2, 5)}`;
          
          // Create candidates with IDs and zero votes
          const electionCandidates = electionInput.candidates.map((candidate, index) => ({
            id: `${electionId}-${index + 1}`,
            name: candidate.name,
            party: candidate.party,
            position: candidate.position,
            image: candidate.image,
            votes: 0
          }));
          
          // Create the election
          const newElection: Election = {
            id: electionId,
            title: electionInput.title,
            description: electionInput.description,
            position: electionInput.position,
            createdBy: electionInput.createdBy,
            createdAt: Date.now(),
            candidates: electionCandidates,
            voteLimit: electionInput.voteLimit,
            endTime: electionInput.endTime
          };
          
          setElections(prev => [...prev, newElection]);
          
          // Add all candidates to the global candidates list
          setCandidates(prev => [...prev, ...electionCandidates]);
          
          setIsLoading(false);
          resolve(electionId);
        } catch (error) {
          console.error('Error creating election:', error);
          toast.error('Failed to create election');
          setIsLoading(false);
          resolve('');
        }
      }, 1500);
    });
  };

  const castVote = async (candidateId: string, voterId: string, electionId?: string): Promise<boolean> => {
    setIsLoading(true);
    
    const targetElectionId = electionId || currentElectionId;
    
    return new Promise((resolve) => {
      setTimeout(() => {
        try {
          // Find the election
          const election = elections.find(e => e.id === targetElectionId);
          if (!election) {
            toast.error('Election not found');
            setIsLoading(false);
            resolve(false);
            return;
          }
          
          // Check if voter has already voted for this election
          if (blockchain.some(block => block.voter === voterId && block.election === targetElectionId && block.voter !== 'GENESIS')) {
            toast.error('You have already voted in this election!');
            setIsLoading(false);
            resolve(false);
            return;
          }
          
          // 1. Check if candidate exists in this election
          const candidateIndex = election.candidates.findIndex(c => c.id === candidateId);
          if (candidateIndex === -1) {
            toast.error('Invalid candidate for this election');
            setIsLoading(false);
            resolve(false);
            return;
          }
          
          // 2. Create a new block
          const previousBlock = blockchain[blockchain.length - 1];
          const newBlock: Omit<Block, 'hash'> = {
            id: blockchain.length.toString(),
            timestamp: Date.now(),
            voter: voterId,
            candidate: candidateId,
            election: targetElectionId,
            previousHash: previousBlock.hash
          };
          
          // 3. Calculate block hash
          const hash = hashBlock(newBlock);
          
          // 4. Add block to chain
          const block: Block = {
            ...newBlock,
            hash
          };
          
          setBlockchain([...blockchain, block]);
          
          // 5. Update candidate votes in the election
          setElections(prev => prev.map(e => {
            if (e.id === targetElectionId) {
              return {
                ...e,
                candidates: e.candidates.map(c => 
                  c.id === candidateId 
                    ? { ...c, votes: c.votes + 1 }
                    : c
                )
              };
            }
            return e;
          }));
          
          // 6. Update candidate votes in global candidates list
          setCandidates(prev => prev.map(c => 
            c.id === candidateId 
              ? { ...c, votes: c.votes + 1 }
              : c
          ));
          
          toast.success('Vote recorded on the blockchain!');
          setIsLoading(false);
          resolve(true);
        } catch (error) {
          console.error('Error casting vote:', error);
          toast.error('Failed to record your vote');
          setIsLoading(false);
          resolve(false);
        }
      }, 2000); // Simulate blockchain transaction time
    });
  };

  const getResults = (electionId?: string): Candidate[] => {
    const targetElectionId = electionId || currentElectionId;
    const election = elections.find(e => e.id === targetElectionId);
    
    if (!election) {
      return [...candidates].sort((a, b) => b.votes - a.votes);
    }
    
    return [...election.candidates].sort((a, b) => b.votes - a.votes);
  };

  const addCandidate = async (candidate: Omit<Candidate, 'id' | 'votes'>): Promise<boolean> => {
    setIsLoading(true);
    
    return new Promise((resolve) => {
      setTimeout(() => {
        try {
          const newCandidate: Candidate = {
            ...candidate,
            id: (candidates.length + 1).toString(),
            votes: 0
          };
          
          setCandidates([...candidates, newCandidate]);
          
          // Also add the candidate to the current election
          setElections(prev => prev.map(e => {
            if (e.id === currentElectionId) {
              return {
                ...e,
                candidates: [...e.candidates, newCandidate]
              };
            }
            return e;
          }));
          
          toast.success('Candidate added successfully!');
          setIsLoading(false);
          resolve(true);
        } catch (error) {
          console.error('Error adding candidate:', error);
          toast.error('Failed to add candidate');
          setIsLoading(false);
          resolve(false);
        }
      }, 1000);
    });
  };

  return (
    <BlockchainContext.Provider
      value={{
        candidates,
        blockchain,
        elections,
        isLoading,
        castVote,
        getResults,
        addCandidate,
        createElection,
        getElection,
        getCurrentElection,
        setCurrentElection,
        getAllElections
      }}
    >
      {children}
    </BlockchainContext.Provider>
  );
};

export const useBlockchain = (): BlockchainContextType => {
  const context = useContext(BlockchainContext);
  if (context === undefined) {
    throw new Error('useBlockchain must be used within a BlockchainProvider');
  }
  return context;
};
