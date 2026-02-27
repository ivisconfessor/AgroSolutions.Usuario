using AgroSolutions.Usuario.Infra;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

var jwtOptions = builder.Configuration.GetSection("Jwt").Get<JwtOptions>()
                 ?? throw new InvalidOperationException("Configuração 'Jwt' não encontrada.");

// ✅ REGISTRO SERVIÇOS
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddDbContext<UsuarioDbContext>(options =>
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
    if (string.IsNullOrWhiteSpace(connectionString))
    {
        throw new InvalidOperationException("ConnectionStrings:DefaultConnection não está configurada.");
    }

    options.UseNpgsql(connectionString);
});
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtOptions.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.SigningKey)),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };
    });
builder.Services.AddAuthorization();

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo 
    { 
        Title = "AgroSolutions.Usuario.Api", 
        Version = "v1",
        Description = "[HACKATON FIAP] Microserviço responsável pela autenticação do usuário (Produto Rural)."
    });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header. Informe: Bearer {seu_token}",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader();
    });
});

// ✅ BUILD
var app = builder.Build();

// ✅ CONFIGURA PIPELINE HTTP
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "[HACKATON FIAP] - AgroSolutions.Usuario.Api v1");
        options.RoutePrefix = "swagger";
    });
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.UseCors("AllowAll");

app.MapPost("/login", async (LoginRequest request, UsuarioDbContext db) =>
{
    if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Senha))
        return Results.BadRequest(new { mensagem = "E-mail e senha são obrigatórios." });

    var usuario = await db.Usuarios
        .AsNoTracking()
        .SingleOrDefaultAsync(u => u.Email == request.Email && u.Ativo);

    if (usuario is null)
        return Results.Unauthorized();

    var senhaValida = BCrypt.Net.BCrypt.Verify(request.Senha, usuario.SenhaHash);
    if (!senhaValida)
        return Results.Unauthorized();

    var now = DateTime.UtcNow;
    var expiryMinutes = jwtOptions.ExpiryMinutes <= 0 ? 60 : jwtOptions.ExpiryMinutes;
    var expiresAtUtc = now.AddMinutes(expiryMinutes);

    var claims = new List<Claim>
    {
        new(JwtRegisteredClaimNames.Sub, usuario.IdUsuario.ToString()),
        new(JwtRegisteredClaimNames.Email, usuario.Email),
        new("nome", usuario.Nome),
        new(ClaimTypes.Role, "ProdutorRural")
    };

    var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.SigningKey));
    var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        issuer: jwtOptions.Issuer,
        audience: jwtOptions.Audience,
        claims: claims,
        notBefore: now,
        expires: expiresAtUtc,
        signingCredentials: credentials
    );

    var tokenValue = new JwtSecurityTokenHandler().WriteToken(token);

    return Results.Ok(new LoginResponse(
        Token: tokenValue,
        ExpiresAtUtc: expiresAtUtc,
        Usuario: new UsuarioResponse(
            Id: usuario.IdUsuario.ToString(),
            Email: usuario.Email,
            Nome: usuario.Nome
        )));
})
.WithName("Login")
.WithOpenApi();

app.Run();

record JwtOptions(string Issuer, string Audience, string SigningKey, int ExpiryMinutes);
record LoginRequest(string Email, string Senha);
record UsuarioResponse(string Id, string Email, string? Nome);
record LoginResponse(string Token, DateTime ExpiresAtUtc, UsuarioResponse Usuario);
