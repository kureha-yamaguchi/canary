import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "UK AISI Admin Dashboard",
  description: "United Kingdom Association of Incompetent Security Investigators - Admin Portal",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
