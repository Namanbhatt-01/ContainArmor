using ContainArmor.Blazor.Components;
using ContainArmor.Blazor.Services;
using ContainArmor.Engine;

var builder = WebApplication.CreateBuilder(args);

// Register ContainArmor Engine & Services
builder.Services.AddContainArmorEngine();
builder.Services.AddScoped<ContainArmorStateService>();

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
}

app.UseAntiforgery();
app.UseStaticFiles();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
