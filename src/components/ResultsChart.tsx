
import React from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell
} from "recharts";

interface Candidate {
  id: string;
  name: string;
  party: string;
  position: string;
  votes: number;
}

interface ResultsChartProps {
  candidates: Candidate[];
}

const ResultsChart = ({ candidates }: ResultsChartProps) => {
  const sortedCandidates = [...candidates].sort((a, b) => b.votes - a.votes);
  
  // Format data for chart
  const data = sortedCandidates.map(candidate => ({
    name: candidate.name,
    votes: candidate.votes,
    party: candidate.party
  }));
  
  // Generate colors based on position
  const getBarColor = (index: number) => {
    const colors = ["#8B5CF6", "#6E59A5", "#D6BCFA", "#9333EA", "#C084FC"];
    return colors[index % colors.length];
  };
  
  // Custom tooltip
  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white p-4 rounded-md shadow-lg border border-gray-200">
          <p className="text-vote-primary font-bold">{label}</p>
          <p className="text-gray-600">{payload[0].payload.party}</p>
          <p className="text-vote-secondary font-medium">
            {payload[0].value} votes
          </p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="w-full h-[400px]">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          margin={{ top: 20, right: 30, left: 20, bottom: 60 }}
        >
          <CartesianGrid strokeDasharray="3 3" vertical={false} />
          <XAxis 
            dataKey="name" 
            angle={-45} 
            textAnchor="end" 
            height={70}
            tick={{ fontSize: 12 }}
          />
          <YAxis 
            label={{ 
              value: 'Votes', 
              angle: -90, 
              position: 'insideLeft',
              style: { textAnchor: 'middle', fill: '#666' },
              dx: -10
            }} 
          />
          <Tooltip content={<CustomTooltip />} />
          <Bar dataKey="votes" radius={[4, 4, 0, 0]}>
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={getBarColor(index)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export default ResultsChart;
