/* eslint-disable no-undef */
const withMT = require("@material-tailwind/react/utils/withMT");
export default withMT({
  darkMode: ["class"],
  content: [
    "./index.html",
    "./src/**/*.{vue,js,ts,jsx,tsx}",
    "./node_modules/@material-tailwind/react/components/**/*.{js,ts,jsx,tsx}",
    "./node_modules/@material-tailwind/react/theme/components/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        theme: {
          '50': '#eff3ff',
          '100': '#dbe3fe',
          '200': '#c0cefd',
          '300': '#94affc',
          '400': '#6185f9',
          '500': '#3354f4',
          '600': '#273ce9',
          '700': '#1e28d7',
          '800': '#1f23ae',
          '900': '#1f2489',
          '950': '#171854',


        },
      },
      fontFamily: {
        Nunito: ['Nunito'],
        body: ['Nunito']
      }
    }
  },
  plugins: [require("tailwindcss-animate")],
});
