import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface CodeViewerProps {
  code: string | null | undefined;
  startLine?: number | null;
  filePath?: string;
  language?: string;
  maxHeight?: string;
}

export const CodeViewer: React.FC<CodeViewerProps> = ({
  code,
  startLine = 1,
  filePath,
  maxHeight = 'max-h-72',
}) => {
  const [copied, setCopied] = useState(false);

  if (!code) {
    return (
      <div className="bg-[#111622] rounded border border-[#21262d] p-3 text-xs text-slate-500 font-mono italic">
        No code snippet available
      </div>
    );
  }

  const lines = code.split('\n');
  const baseLine = startLine && startLine > 0 ? startLine : 1;

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-lg border border-[#21262d] bg-[#0d1117] overflow-hidden text-xs font-mono shadow-sm">
      {filePath && (
        <div className="flex items-center justify-between px-3 py-1.5 bg-[#161b22] border-b border-[#21262d] text-slate-400">
          <span className="truncate max-w-md font-medium text-slate-300">{filePath}</span>
          <button
            onClick={handleCopy}
            className="flex items-center gap-1 text-slate-400 hover:text-slate-200 transition-colors p-1 rounded hover:bg-[#21262d]"
            title="Copy snippet"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span className="text-[11px]">{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
      )}

      <div className={`overflow-auto p-2 ${maxHeight}`}>
        <table className="w-full border-collapse">
          <tbody>
            {lines.map((line, idx) => (
              <tr key={idx} className="hover:bg-[#161b22]/50 transition-colors">
                <td className="select-none text-right pr-3 text-slate-600 w-10 py-0.5 border-r border-[#21262d]/50">
                  {baseLine + idx}
                </td>
                <td className="pl-3 py-0.5 whitespace-pre font-mono text-slate-200">
                  {/* Safely rendered plain text, escaped naturally by React */}
                  {line}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
