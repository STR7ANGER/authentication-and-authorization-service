/*
  Warnings:

  - Added the required column `codeVerifierHash` to the `OAuthState` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "OAuthState" ADD COLUMN     "codeVerifierHash" TEXT NOT NULL;
