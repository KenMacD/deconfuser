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

namespace DeConfuser
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Copyright © DragonHunter - 2012");
            Console.WriteLine("This deobfuscator might not work at every confused assembly, still BETA");
            Console.WriteLine("Checkout this project at http://deconfuser.codeplex.com");
            Console.WriteLine("Thanks also to Mono.Cecil there was no DeConfuser without Mono.Cecil");
            Console.WriteLine("This version of Mono.Cecil is modded by DragonHunter to do some evil shit");

            //hardcoded path atm...
            string inputPath = @"F:\DeConfuser\ConfuseMe\bin\Debug\confused\ConfuseMe.exe";
            string outputPath = @"F:\DeConfuser\ConfuseMe\bin\Debug\confused\ConfuseMe_clean.exe";

            AssemblyDefinition asm = AssemblyFactory.GetAssembly(inputPath);
            AntiDebug debug = new AntiDebug();

            TypeDefinition AntiType = null;
            MethodDefinition AntiMethod = null;
            if(debug.FindAntiDebug(asm, ref AntiType, ref AntiMethod))
            {
                Console.WriteLine("Anti-Debugging detected, removing...");
                debug.RemoveAntiDebug(asm, AntiType, AntiMethod);
            }
            AssemblyFactory.SaveAssembly(asm, outputPath);
            Console.WriteLine("File dumped to \"" + outputPath + "\"");
            Console.WriteLine("Thanks for using DeConfuser :)");
            Process.GetCurrentProcess().WaitForExit();
        }
    }
}