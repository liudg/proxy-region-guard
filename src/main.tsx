import React from 'react';
import ReactDOM from 'react-dom/client';
import { MainDashboard } from './components/MainDashboard';
import { AlertPopup } from './components/AlertPopup';
import './styles.css';

const isAlertRoute = window.location.hash.includes('alert');
if (isAlertRoute) {
  document.documentElement.classList.add('transparent-root');
  document.body.classList.add('transparent-root');
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>{isAlertRoute ? <AlertPopup /> : <MainDashboard />}</React.StrictMode>
);
