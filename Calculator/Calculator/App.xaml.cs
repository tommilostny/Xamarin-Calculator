using System;
using Xamarin.Forms;
using Xamarin.Forms.Xaml;

namespace Calculator
{
    public partial class App : Application
    {
        public App()
        {
            InitializeComponent();

            if (Device.RuntimePlatform == Device.UWP)
                MainPage = new NavigationPage(new MainPage())
                {
                    BarBackgroundColor = Color.FromHex("#EEEEEE"),
                    BarTextColor = Color.Black
                };

            else MainPage = new NavigationPage(new MainPage());
        }

        protected override void OnStart()
        {
        }

        protected override void OnSleep()
        {
        }

        protected override void OnResume()
        {
        }
    }
}
