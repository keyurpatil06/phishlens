"use client";
import React, { useState } from "react";
import type { ThreatInfo } from "@/lib/threatInfo";
import AwarenessModal from "./AwarenessModal";

export default function AwarenessPanel({ info }: { info?: ThreatInfo | null }) {
  const [open, setOpen] = useState(false);
  if (!info) return null;

  return (
    <>
      <aside className="p-4 bg-card rounded-md shadow-sm border border-border">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="text-base font-semibold">{info.title}</h3>
            <p className="text-sm mt-1 text-muted-foreground">{info.explanation}</p>
          </div>
          <div className="text-sm">
            <span className="inline-block px-2 py-1 rounded-full bg-yellow-100 text-yellow-800 text-xs">
              {info.severity?.toUpperCase() ?? "INFO"}
            </span>
          </div>
        </div>

        <ul className="mt-3 list-disc pl-5 text-sm space-y-1">
          {info.tips.slice(0, 3).map((t, i) => (
            <li key={i}>{t}</li>
          ))}
        </ul>

        <div className="mt-3 flex gap-2">
          <button
            onClick={() => setOpen(true)}
            className="inline-flex items-center px-3 py-1.5 border rounded text-sm hover:bg-muted"
          >
            Learn more
          </button>
        </div>
      </aside>

      {open && <AwarenessModal info={info} onClose={() => setOpen(false)} />}
    </>
  );
}
