# Taesa.Auth

Autenticação para aplicações ASP .NET Core. Esse pacote auxilia a implementaçao do login único Taesa via Piaget

## Instruções

### Instalação
Instalação do pacote _Taesa.Auth_ [NuGet package](https://www.nuget.org/packages/Taesa.Auth/) na sua aplicação.

```shell
dotnet add package Taesa.Auth
```

### Configuração

Adicione o TaesaAuthService ao serviços da sua aplicação
```csharp
public void ConfigureServices(IServiceCollection services)
{
    
    //...

    SecurityKey key; // Criar alguma SecurityKey 

    // Não inserir usuário e senha hardcoded, use arquivo de configuração, variáveis de ambiente, parametros de inicialização, adivinhação, milagre etc

    services.AddAuthorizationTaesa(key, new TaesaAuthSettings(){
        Url = "https://urldelogin.taesa.com.br",
        User = "aplicação-user", 
        Password = "Senha da aplicação" 
    });
    
    //...

    services.AddAuthenticationTaesa(key);
    
    // OU

    services.AddAuthenticationTaesa(key, options => {

     //...

    });


}

```

### Geração do token

```csharp
public async Task<ActionResult> Login([FromBody] LoginRequest request, [FromServices] TaesaAuthService authService){
    var token = await authService.LoginAsync(request.ChaveAcesso);

    //Informações do usuário contindas no token
    var user = authService.GetUser(token);

    // ...

    return Ok(token);
}
```