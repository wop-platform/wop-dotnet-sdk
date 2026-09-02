// 公共 API 快照生成器：为 src/Wop.Sdk 的每个 TFM 生成 PublicAPI.Unshipped.txt。
//
// 行格式与 Microsoft.CodeAnalysis.PublicApiAnalyzers 3.3.4 完全一致（同源复刻）：
//   DeclarePublicApiAnalyzer.s_publicApiFormatWithNullability
//     = s_publicApiFormat.WithMiscellaneousOptions(
//         UseSpecialTypes | IncludeNullableReferenceTypeModifier(1<<6)
//                          | IncludeNonNullableReferenceTypeModifier(1<<8))
//   行文本 = symbol.ToDisplayString(fmt) [+ " -> " + memberType.ToDisplayString(fmt)]
// tracked-symbol 判定同 DeclarePublicApiAnalyzer.Impl.IsTrackedAPI（isPublic: true）：
//   - EventAdd/EventRemove 跳过；属性本身跳过（其 get/set accessor 进快照）
//   - GetResultantVisibility == Public（复刻 Analyzer.Utilities ISymbolExtensions）
//   - protected / protected-or-internal 成员要求容器类型可被继承（CanTypeBeExtended）
// 生成后以 `dotnet build -warnaserror` 校准：RS0016/RS0017 残留即格式偏差信号。
//
// 用法（仓库根）：dotnet run --project tools/gen-publicapi

using Microsoft.Build.Locator;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.MSBuild;

if (args.Length > 1)
{
    Console.Error.WriteLine("用法：dotnet run --project tools/gen-publicapi [--check]");
    return 2;
}
bool checkOnly = args.Length == 1 && args[0] == "--check";

MSBuildLocator.RegisterDefaults();

var repoRoot = FindRepoRoot(AppContext.BaseDirectory);
var csproj = Path.Combine(repoRoot, "src", "Wop.Sdk", "Wop.Sdk.csproj");
if (!File.Exists(csproj))
{
    Console.Error.WriteLine($"未找到主库项目：{csproj}");
    return 2;
}

string[] tfms = ["net8.0", "netstandard2.0"];
int mismatches = 0;

foreach (var tfm in tfms)
{
    // 多目标项目：MSBuildWorkspace.Create 时钉 TargetFramework 全局属性（4.8 的
    // OpenProjectAsync 无 properties 参数，属性只能在 workspace 级注入）。
    using var workspace = MSBuildWorkspace.Create(
        new Dictionary<string, string> { ["TargetFramework"] = tfm });
    workspace.WorkspaceFailed += (_, e) => Console.Error.WriteLine($"[workspace] {e.Diagnostic.Message}");

    var project = await workspace.OpenProjectAsync(csproj);
    if (workspace.Diagnostics.Any(d => d.Kind == WorkspaceDiagnosticKind.Failure))
    {
        Console.Error.WriteLine($"[{tfm}] 工作区加载失败：{string.Join("; ", workspace.Diagnostics)}");
        return 3;
    }
    var compilation = await project.GetCompilationAsync()
        ?? throw new InvalidOperationException($"[{tfm}] 无法获取 Compilation");

    var lines = new SortedSet<string>(StringComparer.Ordinal);
    VisitNamespace(compilation.Assembly.GlobalNamespace, lines);

    var apiDir = Path.Combine(repoRoot, "src", "Wop.Sdk", "PublicAPI", tfm);
    var unshipped = Path.Combine(apiDir, "PublicAPI.Unshipped.txt");
    var shipped = Path.Combine(apiDir, "PublicAPI.Shipped.txt");

    var content = "#nullable enable" + Environment.NewLine
        + string.Join(Environment.NewLine, lines) + Environment.NewLine;

    if (checkOnly)
    {
        var current = File.Exists(unshipped) ? File.ReadAllText(unshipped) : "";
        if (!string.Equals(Normalize(current), Normalize(content), StringComparison.Ordinal))
        {
            Console.Error.WriteLine($"[{tfm}] 公共 API 快照漂移：{unshipped} 与当前代码不一致，请再生成并随变更一并提交。");
            mismatches++;
        }
        continue;
    }

    Directory.CreateDirectory(apiDir);
    // Shipped 留空（未发版面）：当前所有 API 均为 Unshipped。
    File.WriteAllText(shipped, "#nullable enable" + Environment.NewLine);
    File.WriteAllText(unshipped, content);
    Console.WriteLine($"[{tfm}] 生成 {lines.Count} 行 API -> {Path.GetRelativePath(repoRoot, unshipped)}");
}

return checkOnly ? (mismatches == 0 ? 0 : 1) : 0;

static string Normalize(string s) => s.Replace("\r\n", "\n").TrimEnd('\n');

static string FindRepoRoot(string start)
{
    var dir = new DirectoryInfo(start);
    while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Wop.Sdk.sln")))
        dir = dir.Parent;
    return dir?.FullName ?? throw new InvalidOperationException("未找到仓库根（Wop.Sdk.sln）");
}

static void VisitNamespace(INamespaceSymbol ns, SortedSet<string> lines)
{
    foreach (var nested in ns.GetNamespaceMembers())
        VisitNamespace(nested, lines);
    foreach (var type in ns.GetTypeMembers())
        VisitType(type, lines);
}

static void VisitType(INamedTypeSymbol type, SortedSet<string> lines)
{
    MaybeTrack(type, lines);
    foreach (var nested in type.GetTypeMembers())
        VisitType(nested, lines);

    foreach (var member in type.GetMembers())
    {
        switch (member)
        {
            case IMethodSymbol { MethodKind: MethodKind.EventAdd or MethodKind.EventRemove }:
                break;
            case IPropertySymbol:
                // 属性本身不进快照（analyzer 同款语义）；其 accessor 在 GetMembers 的
                // IMethodSymbol（AssociatedSymbol 指回属性）中处理。
                break;
            case ISymbol s:
                MaybeTrack(s, lines);
                break;
        }
    }

    // 隐式公共构造器（analyzer OnSymbolActionCore 同款）：class 恰好一个实例构造器、
    // 或 struct 的隐式构造器，编译器合成但属于公共 API 面。
    if ((type.TypeKind == TypeKind.Class && type.InstanceConstructors.Length == 1)
        || type.TypeKind == TypeKind.Struct)
    {
        var implicitCtor = type.InstanceConstructors.FirstOrDefault(c => c.IsImplicitlyDeclared);
        if (implicitCtor != null)
            MaybeTrack(implicitCtor, lines);
    }
}

static void MaybeTrack(ISymbol symbol, SortedSet<string> lines)
{
    if (symbol is IMethodSymbol { MethodKind: MethodKind.EventAdd or MethodKind.EventRemove })
        return;
    if (symbol is IPropertySymbol)
        return;

    // 合成成员（IsImplicitlyDeclared：enum value__ 与隐式 ctor、delegate 合成方法、
    // record 合成成员）不会触发 analyzer 的 RegisterSymbolAction 回调 → 不进快照。
    // 例外（analyzer 显式补录）：属性 accessor（OnPropertyAction 补隐式 get_/set_）
    // 与 class（恰一个实例构造器）/struct 的隐式构造器（OnSymbolActionCore 补录）。
    // 注意合成成员的 Locations 常指向类型声明处，IsInSource 不能作为判据。
    if (symbol.IsImplicitlyDeclared)
    {
        bool isPropertyAccessor = symbol is IMethodSymbol { MethodKind: MethodKind.PropertyGet or MethodKind.PropertySet };
        bool isImplicitCtor = symbol is IMethodSymbol { MethodKind: MethodKind.Constructor }
            && symbol.ContainingType is { TypeKind: TypeKind.Class or TypeKind.Struct } t
            && (t.TypeKind != TypeKind.Class || t.InstanceConstructors.Length == 1);
        if (!isPropertyAccessor && !isImplicitCtor)
            return;
    }

    if (!IsTrackedPublicApi(symbol))
        return;

    lines.Add(ApiLine(symbol));
}

// === 以下复刻 DeclarePublicApiAnalyzer.Impl（v3.3.4，isPublic: true） ===

static ApiGate.Vis GetResultantVisibility(ISymbol symbol)
{
    // 复刻 Analyzer.Utilities ISymbolExtensions.GetResultantVisibility（v3.3.4）：
    // NotApplicable/Private → Private；Internal/ProtectedAndInternal 降为 Internal；
    // Public/Protected/ProtectedOrInternal 保持。沿 ContainingSymbol 链取最严值。
    var visibility = ApiGate.Vis.Public;
    var current = symbol;
    while (current != null && current.Kind != SymbolKind.Namespace)
    {
        switch (current.DeclaredAccessibility)
        {
            case Accessibility.NotApplicable:
            case Accessibility.Private:
                return ApiGate.Vis.Private;
            case Accessibility.Internal:
            case Accessibility.ProtectedAndInternal:
                visibility = ApiGate.Vis.Internal;
                break;
        }
        current = current.ContainingSymbol;
    }
    return visibility;
}

static bool IsTrackedPublicApi(ISymbol symbol)
{
    var resultant = GetResultantVisibility(symbol);
    if (resultant != ApiGate.Vis.Public)
        return false;

    for (var current = symbol; current is INamedTypeSymbol; current = current.ContainingType)
    {
        switch (current.DeclaredAccessibility)
        {
            case Accessibility.Protected:
            case Accessibility.ProtectedOrInternal:
                if (!CanTypeBeExtended(current.ContainingType))
                    return false;
                break;
        }
    }
    return true;
}

static bool CanTypeBeExtended(ITypeSymbol type)
{
    if (type == null)
        return false;
    return !type.IsSealed && type.GetMembers(WellKnownMemberNames.InstanceConstructorName).Any(
        m => m.DeclaredAccessibility switch
        {
            Accessibility.Internal or Accessibility.ProtectedAndInternal => false,
            Accessibility.Private => false,
            _ => true,
        });
}

static string ApiLine(ISymbol symbol)
{
    var format = ApiGate.PublicApiFormatWithNullability;
    var text = symbol.ToDisplayString(format);

    ITypeSymbol? memberType = symbol switch
    {
        IMethodSymbol m => m.ReturnType,
        IEventSymbol e => e.Type,
        IFieldSymbol f => f.Type,
        _ => null,
    };
    if (memberType != null)
        text += " -> " + memberType.ToDisplayString(format);
    return text;
}

internal static class ApiGate
{

    internal enum Vis { Public = 0, Internal = 1, Private = 2 }

    internal static readonly SymbolDisplayFormat PublicApiFormat = new(
        globalNamespaceStyle: SymbolDisplayGlobalNamespaceStyle.OmittedAsContaining,
        typeQualificationStyle: SymbolDisplayTypeQualificationStyle.NameAndContainingTypesAndNamespaces,
        propertyStyle: SymbolDisplayPropertyStyle.ShowReadWriteDescriptor,
        genericsOptions: SymbolDisplayGenericsOptions.IncludeTypeParameters,
        memberOptions:
            SymbolDisplayMemberOptions.IncludeParameters |
            SymbolDisplayMemberOptions.IncludeContainingType |
            SymbolDisplayMemberOptions.IncludeExplicitInterface |
            SymbolDisplayMemberOptions.IncludeModifiers |
            SymbolDisplayMemberOptions.IncludeConstantValue,
        parameterOptions:
            SymbolDisplayParameterOptions.IncludeExtensionThis |
            SymbolDisplayParameterOptions.IncludeParamsRefOut |
            SymbolDisplayParameterOptions.IncludeType |
            SymbolDisplayParameterOptions.IncludeName |
            SymbolDisplayParameterOptions.IncludeDefaultValue,
        miscellaneousOptions:
            SymbolDisplayMiscellaneousOptions.UseSpecialTypes);

    // 复刻 DeclarePublicApiAnalyzer.s_publicApiFormatWithNullability（v3.3.4）：
    // 1<<6 = IncludeNullableReferenceTypeModifier（内部未公开），1<<8 = IncludeNonNullableReferenceTypeModifier
    internal static readonly SymbolDisplayFormat PublicApiFormatWithNullability = PublicApiFormat.WithMiscellaneousOptions(
        SymbolDisplayMiscellaneousOptions.UseSpecialTypes |
        (SymbolDisplayMiscellaneousOptions)(1 << 6) |
        (SymbolDisplayMiscellaneousOptions)(1 << 8));
}
