import { useTranslation } from 'react-i18next';
import { LanguageIcon } from '@heroicons/react/24/outline';

export default function LanguageSwitcher() {
  const { i18n } = useTranslation();

  const toggleLanguage = () => {
    const newLang = i18n.language === 'zh' ? 'en' : 'zh';
    i18n.changeLanguage(newLang);
  };

  return (
    <button
      onClick={toggleLanguage}
      className="flex items-center gap-2 rounded-lg bg-white/5 px-3 py-1.5 text-xs font-medium text-slate-400 hover:bg-white/10 hover:text-white transition-colors"
      title={i18n.language === 'zh' ? 'Switch to English' : '切换到中文'}
    >
      <LanguageIcon className="h-4 w-4" />
      <span>{i18n.language === 'zh' ? 'EN' : '中文'}</span>
    </button>
  );
}
