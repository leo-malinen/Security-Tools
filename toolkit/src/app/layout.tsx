import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Cybersecurity Tools Hub",
  description: "Home base for security tooling — threat radar, scanners, and monitors.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-black text-slate-200 antialiased">{children}</body>
    </html>
  );
}
