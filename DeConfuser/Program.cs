/*
Copyright (C) 2012 DragonHunter

This file is part of DeConfuser.

DeConfuser is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

DeConfuser is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with DeConfuser. If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using Mono.Cecil;
using System.Diagnostics;
using DeConfuser.Removers;
using Mono.Cecil.Cil;

namespace DeConfuser
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "DeConfuser - The De-Obfuscator for confuser v1.6";
            Console.WriteLine("Copyright © DragonHunter - 2012");
            Console.WriteLine("This deobfuscator might not work at every confused assembly, still BETA");
            Console.WriteLine("Checkout this project at http://deconfuser.codeplex.com");
            Console.WriteLine("Thanks also to Mono.Cecil there was no DeConfuser without Mono.Cecil");
            Console.WriteLine("This version of Mono.Cecil is modded by DragonHunter to do some evil shit");

            //hardcoded path atm...
            string inputPath = @"F:\DeConfuser\ConfuseMe\bin\Debug\confused\ConfuseMe.exe";
            string outputPath = @"F:\DeConfuser\ConfuseMe\bin\Debug\confused\ConfuseMe_clean.exe";

            //load assembly
            AssemblyDefinition asm = AssemblyFactory.GetAssembly(inputPath);

            #region Anti-Debug remover
            AntiDebug debug = new AntiDebug();
            TypeDefinition AntiType = null;
            MethodDefinition AntiMethod = null;
            Console.WriteLine("-------------------------------------------------------");
            if (debug.FindAntiDebug(asm, ref AntiType, ref AntiMethod))
            {
                Console.WriteLine("[Anti-Debugger] Anti-Debugger detected, removing...");
                debug.RemoveAntiDebug(asm, AntiType, AntiMethod);
                Console.WriteLine("[Anti-Debugger] Removed anti-debugger");
            }
            else
            {
                Console.WriteLine("This assembly is not protected with anti-debugging");
            }
            Console.WriteLine("-------------------------------------------------------");
            #endregion

            #region String Decryptor
            StringDecrypter decrypter = new StringDecrypter();
            TypeDefinition DecryptType = null;
            MethodDefinition DecryptMethod = null;
            if (decrypter.FindMethod(asm, ref DecryptType, ref DecryptMethod))
            {
                Console.WriteLine("[String Decryptor] Found string decryptor, decrypting strings...");
                byte[] StringData = decrypter.GetStringResource(asm, inputPath, DecryptMethod);
                decrypter.DecryptAllStrings(asm, DecryptMethod, StringData);
                decrypter.RemoveDecryptMethod(asm, DecryptType, DecryptMethod);
                Console.WriteLine("[String Decryptor] Removed the decrypt method");
            }
            else
            {
                Console.WriteLine("This assembly is not protected with encrypted strings");
            }
            Console.WriteLine("-------------------------------------------------------");
            #endregion

            AssemblyFactory.SaveAssembly(asm, outputPath);
            Console.WriteLine("File dumped to \"" + outputPath + "\"");
            Console.WriteLine("Thanks for using DeConfuser :)");
            Process.GetCurrentProcess().WaitForExit();
        }
    }
}