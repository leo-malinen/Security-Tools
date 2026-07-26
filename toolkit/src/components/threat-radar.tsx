"use client";
import { Radar, IconContainer } from "@/components/ui/radar-effect";
import {
  ShieldAlert,
  Bug,
  KeyRound,
  Network,
  ScanLine,
  FileWarning,
  Lock,
} from "lucide-react";

const ICON = "h-6 w-6 text-sky-500/80";

export default function ThreatRadar() {
  return (
    <section className="flex min-h-screen w-full items-center justify-center bg-black">
      <div className="relative flex h-96 w-full max-w-3xl flex-col items-center justify-center space-y-4 overflow-hidden px-4">
        <div className="mx-auto w-full max-w-3xl">
          <div className="flex w-full items-center justify-center space-x-10 md:justify-between md:space-x-0">
            <IconContainer text="Vuln Scanner" delay={0.2} icon={<ScanLine className={ICON} />} />
            <IconContainer text="Threat Intel" delay={0.4} icon={<ShieldAlert className={ICON} />} />
            <IconContainer text="Malware Sandbox" delay={0.3} icon={<Bug className={ICON} />} />
          </div>
        </div>
        <div className="mx-auto w-full max-w-md">
          <div className="flex w-full items-center justify-center space-x-10 md:justify-between md:space-x-0">
            <IconContainer text="Secrets Audit" delay={0.5} icon={<KeyRound className={ICON} />} />
            <IconContainer text="Network Recon" delay={0.8} icon={<Network className={ICON} />} />
          </div>
        </div>
        <div className="mx-auto w-full max-w-3xl">
          <div className="flex w-full items-center justify-center space-x-10 md:justify-between md:space-x-0">
            <IconContainer text="Log Forensics" delay={0.6} icon={<FileWarning className={ICON} />} />
            <IconContainer text="Cert Monitor" delay={0.7} icon={<Lock className={ICON} />} />
          </div>
        </div>

        <Radar className="absolute -bottom-12" />
        <div className="absolute bottom-0 z-[41] h-px w-full bg-gradient-to-r from-transparent via-slate-700 to-transparent" />
      </div>
    </section>
  );
}
