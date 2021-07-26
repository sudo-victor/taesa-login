using System;
using System.Collections.Generic;

namespace Taesa.Auth
{
    public class User
    {
        public string Iss { get; set; }
        public long Exp { get; set; }
        public string Nome { get; set; }
        public string Email { get; set; }
        public long IdUsuario { get; set; }
        public List<Grupo> Grupos { get; set; }
    }

    public class Grupo
    {
        public AcessoGrupo AcessoGrupo { get; set; }
    }

    public class AcessoGrupo
    {
        public string NmGrupo { get; set; }
        public string DsGrupo { get; set; }
        public long IdAcessoGrupo { get; set; }
        public bool InTemplate { get; set; }
    }
}