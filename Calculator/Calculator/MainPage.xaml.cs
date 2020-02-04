using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xamarin.Forms;

namespace Calculator
{
    // Learn more about making custom code visible in the Xamarin.Forms previewer
    // by visiting https://aka.ms/xamarinforms-previewer
    [DesignTimeVisible(false)]
    public partial class MainPage : ContentPage
    {
        public MainPage()
        {
            InitializeComponent();

            switch (Device.RuntimePlatform)
            {
                case Device.UWP:
                    historyToolbarItem.IconImageSource = "https://img.icons8.com/windows/32/000000/time-machine.png";
                    labelDegRad.Margin = 0;
                    break;
                case Device.Android:
                    backspaceButton.ImageSource = "https://img.icons8.com/windows/64/000000/clear-symbol.png";
                    break;
            }
        }

        double num1 = 0, num2 = 0;
        char operation = char.MinValue;
        History history = new History();
        bool degrees = true;

        private void NumberButton_Clicked(object sender, EventArgs e)
        {
            if (calcLabel.Text.Contains("="))
            {
                ClearValues();
                calcLabel.Text = string.Empty;
                entryLabel.Text = "0";
            }

            if (entryLabel.Text.Length < 20)
            {
                if (entryLabel.Text == "0" && (sender as Button).Text != ".")
                    entryLabel.Text = string.Empty;

                if ((sender as Button).Text == "." && entryLabel.Text.Contains('.'))
                    return;

                entryLabel.Text += (sender as Button).Text;
            }
        }

        private void BackspaceButton_Clicked(object sender, EventArgs e)
        {
            bool clear_all = entryLabel.Text == double.PositiveInfinity.ToString()
                          || entryLabel.Text == double.NaN.ToString();

            entryLabel.Text = entryLabel.Text.Remove(entryLabel.Text.Length - 1);

            if (clear_all || entryLabel.Text == string.Empty || entryLabel.Text == "-")
                entryLabel.Text = "0";

            if (clear_all || calcLabel.Text.Contains("="))
                calcLabel.Text = string.Empty;
        }

        private async void SingleOperationButton_Clicked(object sender, EventArgs e)
        {
            try
            {
                double number = Convert.ToDouble(entryLabel.Text);
                double result = 0;
                string calc_text = string.Empty;
                bool save_to_history = false;

                if (calcLabel.Text.Contains("=") || calcLabel.Text == string.Empty)
                {
                    ClearValues();
                    calcLabel.Text = string.Empty;
                    save_to_history = true;
                }

                switch ((sender as Button).Text)
                {
                    case "1/x":
                        result = 1 / number;
                        calc_text = $"1 / {number} =";
                        break;
                    case "x²":
                        result = Math.Pow(number, 2);
                        calc_text = $"{number} ^ 2 =";
                        break;
                    case "√":
                        result = Math.Sqrt(number);
                        calc_text = $"√({number}) =";
                        break;
                    case "±":
                        result = -1 * number;
                        calc_text = $"-({number}) =";
                        break;
                    case "sin":
                        if (degrees)
                        {
                            result = Math.Sin((number * Math.PI) / 180);
                            calc_text = $"sin({number}°) =";
                        }
                        else
                        {
                            result = Math.Sin(number);
                            calc_text = $"sin({number} rad) =";
                        }
                        break;
                    case "cos":
                        if (degrees)
                        {
                            result = Math.Cos((number * Math.PI) / 180);
                            calc_text = $"cos({number}°) =";
                        }
                        else
                        {
                            result = Math.Cos(number);
                            calc_text = $"cos({number} rad) =";
                        }
                        break;
                    case "tan":
                        if (degrees)
                        {
                            result = Math.Tan((number * Math.PI) / 180);
                            calc_text = $"tan({number}°) =";
                        }
                        else
                        {
                            result = Math.Tan(number);
                            calc_text = $"tan({number} rad) =";
                        }
                        break;
                    case "cotg":
                        if (degrees)
                        {
                            result = 1 / Math.Tan((number * Math.PI) / 180);
                            calc_text = $"cotg({number}°) =";
                        }
                        else
                        {
                            result = 1 / Math.Tan(number);
                            calc_text = $"cotg({number} rad) =";
                        }
                        break;
                }

                entryLabel.Text = result.ToString();

                if (save_to_history)
                {
                    calcLabel.Text = calc_text;
                    history.AddToList(new Calc
                    {
                        Calculation = calcLabel.Text,
                        Result = entryLabel.Text
                    });
                }
            }
            catch (FormatException)
            {
                await DisplayAlert("Error", "Wrong number entered", "Ok");
            }
        }

        private async void DoubleOperationButton_Clicked(object sender, EventArgs e)
        {
            try
            {
                if (num2 != 0)
                    ClearValues();

                if (num1 == 0)
                    num1 = Convert.ToDouble(entryLabel.Text);

                switch ((sender as Button).Text)
                {
                    case "+":
                        operation = '+';
                        break;
                    case "-":
                        operation = '-';
                        break;
                    case "⨯":
                        operation = '⨯';
                        break;
                    case "÷":
                        operation = '÷';
                        break;
                    case "x^y":
                        operation = '^';
                        break;
                }

                entryLabel.Text = "0";
                calcLabel.Text = num1.ToString() + ' ' + operation;
            }
            catch (FormatException)
            {
                await DisplayAlert("Error", "Wrong number entered", "Ok");
            }
        }

        private async void EqualsButton_Clicked(object sender, EventArgs e)
        {
            try
            {
                if (num2 == 0)
                    num2 = Convert.ToDouble(entryLabel.Text);
                else
                    num1 = Convert.ToDouble(entryLabel.Text);
                double result = 0;

                switch (operation)
                {
                    case '+':
                        result = num1 + num2;
                        break;
                    case '-':
                        result = num1 - num2;
                        break;
                    case '⨯':
                        result = num1 * num2;
                        break;
                    case '÷':
                        if (num2 != 0)
                            result = num1 / num2;
                        else throw new DivideByZeroException();
                        break;
                    case '^':
                        result = Math.Pow(num1, num2);
                        break;
                    default:
                        return;
                }

                entryLabel.Text = result.ToString();
                calcLabel.Text = num1.ToString() + ' ' + operation + ' ' + num2.ToString() + " =";

                history.AddToList(new Calc
                {
                    Calculation = calcLabel.Text,
                    Result = entryLabel.Text
                });
            }
            catch (FormatException)
            {
                await DisplayAlert("Error", "Wrong number entered", "Ok");
            }
            catch (DivideByZeroException)
            {
                await DisplayAlert("Error", "Cannot divide by zero", "Ok");
            }
        }

        private void ClearValues()
        {
            num1 = num2 = 0;
            operation = char.MinValue;
        }

        private void ClearButton_Clicked(object sender, EventArgs e)
        {
            calcLabel.Text = string.Empty;
            entryLabel.Text = "0";
            ClearValues();
        }

        private async void HistoryToolbarItem_Clicked(object sender, EventArgs e)
        {
            await Navigation.PushAsync(history);
        }

        private async void PiButton_Clicked(object sender, EventArgs e)
        {
            if (entryLabel.Text == "0")
            {
                entryLabel.Text = Math.PI.ToString();

                if (calcLabel.Text.Contains("="))
                    calcLabel.Text = string.Empty;
            }
            else
            {
                try
                {
                    double number = Convert.ToDouble(entryLabel.Text);
                    entryLabel.Text = (number * Math.PI).ToString();

                    if (calcLabel.Text == string.Empty || calcLabel.Text.Contains("="))
                    {
                        ClearValues();

                        calcLabel.Text = number.ToString() + "π =";
                        history.AddToList(new Calc
                        {
                            Calculation = calcLabel.Text,
                            Result = entryLabel.Text
                        });
                    }
                }
                catch (FormatException)
                {
                    await DisplayAlert("Error", "Wrong number before π", "Ok");
                }
            }
        }

        private void DegreesButton_Clicked(object sender, EventArgs e)
        {
            degrees = true;
            degButton.TextColor = Color.FromHex("#3867d6");
            radButton.TextColor = Color.Gray;
        }

        private void RadianButton_Clicked(object sender, EventArgs e)
        {
            degrees = false;
            radButton.TextColor = Color.FromHex("#3867d6");
            degButton.TextColor = Color.Gray;
        }

        protected override void OnAppearing()
        {
            base.OnAppearing();

            if (history.SelectedCalc != null && history.SelectedResult != null)
            {
                entryLabel.Text = history.SelectedResult;
                calcLabel.Text = history.SelectedCalc;
                num1 = num2 = 0;
            }
        }
    }
}