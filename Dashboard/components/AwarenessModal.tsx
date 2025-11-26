"use client";
import React from "react";
import type { ThreatInfo } from "@/lib/threatInfo";

export default function AwarenessModal({
  info,
  onClose,
}: {
  info: ThreatInfo;
  onClose: () => void;
}) {
  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center"
    >
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <div className="relative bg-white rounded-lg shadow-lg max-w-2xl w-full p-6 z-10">
        <div className="flex justify-between items-start">
          <h2 className="text-xl font-semibold">{info.title}</h2>
          <button className="text-sm px-2 py-1" onClick={onClose}>
            Close
          </button>
        </div>

        <p className="mt-3 text-sm text-muted-foreground">{info.explanation}</p>

        <h3 className="mt-4 font-medium">Prevention Tips</h3>
        <ul className="list-disc pl-5 mt-2 space-y-2 text-sm">
          {info.tips.map((t, i) => (
            <li key={i}>{t}</li>
          ))}
        </ul>

        <div className="mt-4 flex justify-end">
          <button className="px-3 py-1.5 border rounded" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
