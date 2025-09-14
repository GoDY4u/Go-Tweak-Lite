# Script para eliminar APPS de la lista WPFTweaksDeBloat
# EXCLUYE EXPRESSAMENTE Minecraft y GamingServices
# EJECUTAR COMO ADMINISTRADOR

Write-Host "Iniciando eliminacion de apps preinstaladas..." -ForegroundColor Cyan
Write-Host "SE PRESERVARAN Minecraft y GamingServices." -ForegroundColor Green

# Lista de paquetes a ELIMINAR (la lista completa, excluyendo los que tú quieres guardar)
$appxPackages = @(
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
    "*EclipseManager*",
    "*ActiproSoftwareLLC*",
    "*AdobeSystemsIncorporated.AdobePhotoshopExpress*",
    "*Duolingo-LearnLanguagesforFree*",
    "*PandoraMediaInc*",
    "*CandyCrush*",
    "*BubbleWitch3Saga*",
    "*Wunderlist*",
    "*Flipboard*",
    "*Twitter*",
    "*Facebook*",
    "*Royal Revolt*",
    "*Sway*",
    "*Speed Test*",
    "*Dolby*",
    "*Viber*",
    "*ACGMediaPlayer*",
    "*Netflix*",
    "*OneCalendar*",
    "*LinkedInforWindows*",
    "*HiddenCityMysteryofShadows*",
    "*Hulu*",
    "*HiddenCity*",
    "*AdobePhotoshopExpress*",
    "*HotspotShieldFreeVPN*",
    "*Microsoft.Advertising.Xaml*"
)

foreach ($app in $appxPackages) {
    Write-Host "Intentando eliminar: $app" -ForegroundColor Yellow
    try {
        # Desinstalar para todos los usuarios
        Get-AppxPackage -AllUsers -Name $app | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        # Desinstalar para el usuario actual (por si acaso)
        Get-AppxPackage -Name $app | Remove-AppxPackage -ErrorAction SilentlyContinue
        # Desaprovisionar el paquete para que no vuelva en updates o nuevos usuarios
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -Like $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        Write-Host "    -> OK" -ForegroundColor Green
    }
    catch {
        Write-Host "    -> Fallo (Puede que no estuviera instalado)" -ForegroundColor Red
    }
}

Write-Host "Proceso completado. Reinicia tu equipo para terminar de aplicar los cambios." -ForegroundColor Cyan
pause