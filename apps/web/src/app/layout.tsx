import type { Metadata } from "next";
import "./styles.css";
export const metadata: Metadata = {
  title: "Aegis Identity",
  description: "Hosted authentication and security console",
};
export default function Layout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
