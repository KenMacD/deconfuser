//
// ExceptionHandlerCollection.cs
//
// Author:
//   Jb Evain (jbevain@gmail.com)
//
// Generated by /CodeGen/cecil-gen.rb do not edit
// Wed Sep 27 12:46:53 CEST 2006
//
// (C) 2005 Jb Evain
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

namespace Mono.Cecil.Cil {

	using System;
	using System.Collections;

	using Mono.Cecil.Cil;

	public sealed class ExceptionHandlerCollection : CollectionBase, ICodeVisitable {

		MethodBody m_container;

		public ExceptionHandler this [int index] {
			get { return List [index] as ExceptionHandler; }
			set { List [index] = value; }
		}

		public MethodBody Container {
			get { return m_container; }
		}

		public ExceptionHandlerCollection (MethodBody container)
		{
			m_container = container;
		}

		public void Add (ExceptionHandler value)
		{
			List.Add (value);
		}
        public void AddRange(ExceptionHandlerCollection value)
        {
            foreach (ExceptionHandler handler in value)
                Add(handler);
        }
        public void AddRange(ExceptionHandler[] value)
        {
            foreach (ExceptionHandler handler in value)
                Add(handler);
        }

		public bool Contains (ExceptionHandler value)
		{
			return List.Contains (value);
		}

		public int IndexOf (ExceptionHandler value)
		{
			return List.IndexOf (value);
		}

		public void Insert (int index, ExceptionHandler value)
		{
			List.Insert (index, value);
		}

		public void Remove (ExceptionHandler value)
		{
			List.Remove (value);
		}

		protected override void OnValidate (object o)
		{
			if (! (o is ExceptionHandler))
				throw new ArgumentException ("Must be of type " + typeof (ExceptionHandler).FullName);
		}

		public void Accept (ICodeVisitor visitor)
		{
			visitor.VisitExceptionHandlerCollection (this);
		}
	}
}
