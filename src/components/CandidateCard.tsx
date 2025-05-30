
import React from "react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Vote } from "lucide-react";

interface CandidateCardProps {
  id: string;
  name: string;
  party: string;
  position: string;
  image: string;
  votes?: number;
  showVotes?: boolean;
  onVote?: (id: string) => void;
  isSelected?: boolean;
  disabled?: boolean;
}

const CandidateCard = ({
  id,
  name,
  party,
  position,
  image,
  votes,
  showVotes = false,
  onVote,
  isSelected = false,
  disabled = false,
}: CandidateCardProps) => {
  return (
    <Card className={`w-full h-full transition-all ${isSelected ? 'border-vote-primary border-2' : ''}`}>
      <CardHeader className="pb-2">
        <div className="flex justify-between items-start">
          <div>
            <CardTitle>{name}</CardTitle>
            <CardDescription className="mt-1">{position}</CardDescription>
          </div>
          
          <Badge variant="outline" className="bg-vote-light">
            {party}
          </Badge>
        </div>
      </CardHeader>
      
      <CardContent className="pt-2">
        <div className="relative aspect-[3/2] rounded-md overflow-hidden mb-4">
          <img
            src={image}
            alt={name}
            className="w-full h-full object-cover"
          />
          
          {showVotes && (
            <div className="absolute bottom-0 right-0 bg-vote-primary text-white px-3 py-1 rounded-tl-md font-bold">
              {votes} votes
            </div>
          )}
        </div>
      </CardContent>
      
      <CardFooter>
        {onVote && (
          <Button
            className={`w-full ${
              isSelected
                ? "bg-vote-primary hover:bg-vote-secondary text-white"
                : "border-vote-primary text-vote-primary hover:bg-vote-primary hover:text-white"
            }`}
            variant={isSelected ? "default" : "outline"}
            onClick={() => onVote(id)}
            disabled={disabled}
          >
            <Vote className="mr-2 h-4 w-4" />
            {isSelected ? "Selected" : "Select"}
          </Button>
        )}
      </CardFooter>
    </Card>
  );
};

export default CandidateCard;
