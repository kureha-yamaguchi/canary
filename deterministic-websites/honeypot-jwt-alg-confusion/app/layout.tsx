import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import UserTracker from "@/components/UserTracker";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "def/acc hackathon - london | November 21-23, 2025",
  description: "Build societal defenses against AI threats alongside 70+ builders at the def/acc hackathon in London. November 21-23, 2025.",
  openGraph: {
    title: "def/acc hackathon - london",
    description: "Build societal defenses against AI threats alongside 70+ builders",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <UserTracker />
        {children}
      </body>
    </html>
  );
}
