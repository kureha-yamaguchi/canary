import type { Metadata } from "next";
import { IBM_Plex_Mono, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import UserTracker from "@/components/UserTracker";

const ibmPlexMono = IBM_Plex_Mono({
  weight: ["400", "500", "600", "700"],
  variable: "--font-ibm-plex-mono",
  subsets: ["latin"],
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "NEURALMARKET // AI MODEL MARKETPLACE",
  description: "TRAIN_DEPLOY_MONETIZE // YOUR_AI_MODELS",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${ibmPlexMono.variable} ${jetbrainsMono.variable} antialiased bg-cream dark:bg-charcoal text-charcoal dark:text-cream`}
      >
        <UserTracker />
        {children}
      </body>
    </html>
  );
}
