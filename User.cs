using System;
using System.Collections.Generic;

// ReSharper disable InconsistentNaming

namespace Taesa.Auth
{
    public class UserResponse
    {
        public string Nome { get; set; }
        public string Email { get; set; }
        public int Id_Usuario { get; set; }

        public object Grupos { get; set; }
    }

    public class User : UserResponse
    {
        public new List<Grupo> Grupos { get; set; }
    }

    public class Grupo
    {
        public AcessoGrupo AcessoGrupo { get; set; }
    }

    public class AcessoGrupo
    {
        public string Nm_Grupo { get; set; }
        public string Ds_Grupo { get; set; }
        public int Id_Acesso_Grupo { get; set; }
        public bool In_Template { get; set; }
    }
}