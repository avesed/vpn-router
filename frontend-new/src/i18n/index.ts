import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import zhTranslation from "../locales/zh.json";
import enTranslation from "../locales/en.json";

// Get saved language from localStorage or use browser language
const getSavedLanguage = (): string => {
  const saved = localStorage.getItem("language");
  if (saved && ["zh", "en"].includes(saved)) {
    return saved;
  }
  // Check browser language
  const browserLang = navigator.language.toLowerCase();
  if (browserLang.startsWith("zh")) {
    return "zh";
  }
  return "zh"; // Default to Chinese
};

i18n.use(initReactI18next).init({
  resources: {
    zh: { translation: zhTranslation },
    en: { translation: enTranslation },
  },
  lng: getSavedLanguage(),
  fallbackLng: "zh",
  interpolation: {
    escapeValue: false, // React already escapes values
  },
});

// Save language preference when it changes
i18n.on("languageChanged", (lng) => {
  localStorage.setItem("language", lng);
});

export default i18n;
