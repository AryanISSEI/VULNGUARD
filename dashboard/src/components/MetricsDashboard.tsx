import { useMemo } from 'react';
import { Finding } from '../types';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface Props {
  findings: Finding[];
}

const SEVERITY_COLORS = {
  critical: '#ef4444', // red-500
  high: '#f97316',    // orange-500
  medium: '#eab308',  // yellow-500
  low: '#3b82f6',     // blue-500
  info: '#9ca3af',    // gray-400
};

export function MetricsDashboard({ findings }: Props) {
  const severityData = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => {
      if (f.severity in counts) {
        counts[f.severity as keyof typeof counts]++;
      }
    });

    return Object.entries(counts)
      .filter(([_, count]) => count > 0)
      .map(([name, value]) => ({
        name: name.charAt(0).toUpperCase() + name.slice(1),
        value,
        color: SEVERITY_COLORS[name as keyof typeof SEVERITY_COLORS]
      }));
  }, [findings]);

  const ruleData = useMemo(() => {
    const counts: Record<string, number> = {};
    findings.forEach(f => {
      counts[f.rule] = (counts[f.rule] || 0) + 1;
    });

    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1]) // Sort descending
      .map(([name, value]) => ({ name, count: value }));
  }, [findings]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 p-6">
      {/* Severity Breakdown */}
      <div className="bg-white/[0.02] border border-white/[0.05] rounded-xl p-6">
        <h3 className="text-lg font-medium text-gray-200 mb-6">Severity Breakdown</h3>
        <div className="h-[300px]">
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={5}
                  dataKey="value"
                  label={({ name, percent }) => `${name} ${((percent || 0) * 100).toFixed(0)}%`}
                  labelLine={false}
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', color: '#f3f4f6' }}
                  itemStyle={{ color: '#f3f4f6' }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-full flex items-center justify-center text-gray-500">
              No severity data available
            </div>
          )}
        </div>
      </div>

      {/* Top Rules */}
      <div className="bg-white/[0.02] border border-white/[0.05] rounded-xl p-6">
        <h3 className="text-lg font-medium text-gray-200 mb-6">Top Vulnerabilities</h3>
        <div className="h-[300px]">
          {ruleData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={ruleData}
                layout="vertical"
                margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" horizontal={true} vertical={false} />
                <XAxis type="number" stroke="#9ca3af" />
                <YAxis 
                  type="category" 
                  dataKey="name" 
                  stroke="#9ca3af" 
                  width={150}
                  tick={{ fill: '#d1d5db', fontSize: 12 }}
                />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', color: '#f3f4f6' }}
                  cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                />
                <Bar dataKey="count" fill="#8b5cf6" radius={[0, 4, 4, 0]} barSize={24}>
                  {ruleData.map((_, index) => (
                    <Cell key={`cell-${index}`} fill={index % 2 === 0 ? '#8b5cf6' : '#a78bfa'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-full flex items-center justify-center text-gray-500">
              No rule data available
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
