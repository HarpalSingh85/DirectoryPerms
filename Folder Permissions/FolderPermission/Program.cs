using System;
using System.Collections.Generic;


namespace FolderPermission
{
    class Program
    {
        private static List<string> perms;

        static void Main(string[] args)
        {
            string path = @"C:\";

            FolderPermission perm = new FolderPermission(path);
            perms = perm.GetPermission(path);
            foreach (var item in perms)
            { Console.WriteLine(item); }

            Console.ReadLine();

        }
    }
}
