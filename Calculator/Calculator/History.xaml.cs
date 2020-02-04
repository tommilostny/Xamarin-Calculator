using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xamarin.Forms;

namespace Calculator
{
    [DesignTimeVisible(false)]
    public partial class History : ContentPage
    {
        private List<Calc> calcs { get; set; }
        public string SelectedResult { get; private set; }
        public string SelectedCalc { get; private set; }

        public History()
        {
            InitializeComponent();

            calcs = new List<Calc>();

            if (Device.RuntimePlatform == Device.UWP)
                toolbarItem.IconImageSource = "https://img.icons8.com/windows/512/000000/trash.png";
        }

        public void AddToList(Calc item)
        {
            //calcs.Insert(0, item);

            calcs.Add(item);

            listView.ItemsSource = calcs;
        }

        private void ClearToolbarItem_Clicked(object sender, EventArgs e)
        {
            calcs = new List<Calc>();
            listView.ItemsSource = calcs;
        }

        private async void listView_ItemSelected(object sender, SelectedItemChangedEventArgs e)
        {
            if (e.SelectedItem != null)
            {
                SelectedCalc = (e.SelectedItem as Calc).Calculation;
                SelectedResult = (e.SelectedItem as Calc).Result;

                await Navigation.PopToRootAsync();
            }
        }

        protected override void OnAppearing()
        {
            base.OnAppearing();

            listView.SelectedItem = null;

            SelectedResult = SelectedCalc = null;
        }
    }
}
