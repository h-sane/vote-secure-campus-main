
import React, { useState } from "react";
import { useBlockchain } from "@/context/BlockchainContext";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

const BlockchainExplorer = () => {
  const { blockchain } = useBlockchain();
  const [searchTerm, setSearchTerm] = useState<string>("");
  
  const filteredBlocks = blockchain.filter(block => {
    if (!searchTerm) return true;
    
    const searchLower = searchTerm.toLowerCase();
    return (
      block.id.toLowerCase().includes(searchLower) ||
      block.hash.toLowerCase().includes(searchLower) ||
      block.previousHash.toLowerCase().includes(searchLower) ||
      block.voter.toLowerCase().includes(searchLower) ||
      block.candidate.toLowerCase().includes(searchLower)
    );
  });
  
  // Format timestamp to readable date
  const formatDate = (timestamp: number) => {
    return new Date(timestamp).toLocaleString();
  };
  
  // Truncate hash for display
  const truncateHash = (hash: string) => {
    if (hash.length <= 8) return hash;
    return `${hash.substring(0, 6)}...${hash.substring(hash.length - 6)}`;
  };

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle>Blockchain Explorer</CardTitle>
        <CardDescription>
          View the immutable record of all votes cast in this election
        </CardDescription>
        
        <div className="mt-2">
          <Input 
            placeholder="Search by block ID, hash, or voter ID..." 
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="max-w-md"
          />
        </div>
      </CardHeader>
      
      <CardContent>
        <div className="rounded-md border overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="bg-vote-light">
                <TableHead className="w-[80px]">Block</TableHead>
                <TableHead>Timestamp</TableHead>
                <TableHead>Previous Hash</TableHead>
                <TableHead>Hash</TableHead>
                <TableHead>Voter ID</TableHead>
                <TableHead>Candidate ID</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredBlocks.map((block) => (
                <TableRow key={block.id} className="hover:bg-gray-50">
                  <TableCell className="font-medium">{block.id}</TableCell>
                  <TableCell>{formatDate(block.timestamp)}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {truncateHash(block.previousHash)}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {truncateHash(block.hash)}
                  </TableCell>
                  <TableCell>
                    {block.voter === 'GENESIS' ? (
                      <span className="text-vote-primary font-bold">GENESIS</span>
                    ) : (
                      truncateHash(block.voter)
                    )}
                  </TableCell>
                  <TableCell>
                    {block.candidate === 'GENESIS' ? (
                      <span className="text-vote-primary font-bold">GENESIS</span>
                    ) : (
                      block.candidate
                    )}
                  </TableCell>
                </TableRow>
              ))}
              
              {filteredBlocks.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-10 text-gray-500">
                    No blocks found matching your search
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
};

export default BlockchainExplorer;
