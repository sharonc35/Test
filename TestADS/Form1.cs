using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using syADS;
//using System.DirectoryServices.AccountManagement;


namespace TestADS
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }






        private void button1_Click(object sender, EventArgs e)
        { 
          string ret;
          ADMethodsAccountManagement ADMethods = new ADMethodsAccountManagement();

          //validate the credentials
          bool isValid = ADMethods.IsAuthenticated("sharonc", "S025252800*", "LDAP://DC=SYNEL-COMPANY,DC=LTD" , "");

          if (isValid)
          {
              ret = ADMethods.ADS_CheckIn("sharonc", "postalCode", "LDAP://DC=SYNEL-COMPANY,DC=LTD" , "");
              MessageBox.Show(ret);
          }

        }

        private void button2_Click(object sender, EventArgs e)
        {
            string ret;
            ADMethodsAccountManagement ADMethods = new ADMethodsAccountManagement();
            ret = ADMethods.ADS_GetInfo("sharon cohen", "postalCode", "LDAP://DC=SYNEL-COMPANY,DC=LTD");
            MessageBox.Show(ret);
        }
    }
}
