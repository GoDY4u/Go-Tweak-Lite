# Script de REVERSIÓN COMPLETA para apps eliminadas por WPFTweaksDeBloat
# REINSTALA TODOS los paquetes de la lista original, INCLUYENDO Minecraft y GamingServices por si se borraron.
# EJECUTAR COMO ADMINISTRADOR

Write-Host "Revertiendo eliminacion de apps preinstaladas..." -ForegroundColor Cyan
Write-Host "Reinstalando TODOS los paquetes, incluyendo Minecraft y GamingServices." -ForegroundColor Green

# Lista COMPLETA de paquetes a reinstalar (la lista original completa)
$appxPackagesToReinstall = @(
    "Microsoft.Microsoft3DViewer",
    "Microsoft.AppConnector",
    "Microsoft.BingFinance",
    "Microsoft.BingNews",
    "Microsoft.BingSports",
    "Microsoft.BingTranslator",
    "Microsoft.BingWeather",
    "Microsoft.BingFoodAndDrink",
    "Microsoft.BingHealthAndFitness",
    "Microsoft.BingTravel",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.Messaging",
    "Microsoft.MinecraftUWP",           # <- AÑADIDO
    "Microsoft.GamingServices",         # <- AÑADIDO
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.NetworkSpeedTest",
    "Microsoft.News",
    "Microsoft.Office.Lens",
    "Microsoft.Office.Sway",
    "Microsoft.Office.OneNote",
    "Microsoft.OneConnect",
    "Microsoft.People",
    "Microsoft.Print3D",
    "Microsoft.SkypeApp",
    "Microsoft.Wallet",
    "Microsoft.Whiteboard",
    "Microsoft.WindowsAlarms",
    "microsoft.windowscommunicationsapps",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsMaps",
    "Microsoft.WindowsSoundRecorder",
    "Microsoft.ConnectivityStore",
    "Microsoft.ScreenSketch",
    "Microsoft.MixedReality.Portal",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "Microsoft.MicrosoftOfficeHub",
    "EclipseManager",
    "ActiproSoftwareLLC",
    "AdobeSystemsIncorporated.AdobePhotoshopExpress",
    "Duolingo-LearnLanguagesforFree",
    "PandoraMediaInc",
    "CandyCrush",
    "BubbleWitch3Saga",
    "Wunderlist",
    "Flipboard",
    "Twitter",
    "Facebook",
    "Royal Revolt",
    "Sway",
    "Speed Test",
    "Dolby",
    "Viber",
    "ACGMediaPlayer",
    "Netflix",
    "OneCalendar",
    "LinkedInforWindows",
    "HiddenCityMysteryofShadows",
    "Hulu",
    "HiddenCity",
    "AdobePhotoshopExpress",
    "HotspotShieldFreeVPN",
    "Microsoft.Advertising.Xaml"
)

foreach ($app in $appxPackagesToReinstall) {
    Write-Host "Intentando restaurar: $app" -ForegroundColor Yellow
    try {
        # Intenta reinstalar desde la ubicación de instalación residual (si existe)
        Get-AppxPackage -AllUsers -Name $app | ForEach-Object {
            Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue
        }
        # Intenta reinstalar usando la ruta del sistema para apps provisionadas
        Add-AppxPackage -DisableDevelopmentMode -Register "$($env:SystemRoot)\SystemApps\$app*\\AppXManifest.xml" -ErrorAction SilentlyContinue
        Write-Host "    -> Reinstalacion intentada" -ForegroundColor Green
    }
    catch {
        Write-Host "    -> No se pudo reinstalar (puede requerir descarga manual de Store)" -ForegroundColor Red
    }
}

Write-Host "Proceso de reversión completado." -ForegroundColor Cyan
Write-Host "NOTA: Es posible que algunas apps necesiten ser instaladas manualmente desde Microsoft Store si los archivos del sistema se borraron." -ForegroundColor Yellow
Write-Host "Reinicia tu equipo si es necesario." -ForegroundColor Cyan
pause