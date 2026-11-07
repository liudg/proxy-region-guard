import React, { Suspense } from 'react';
import ReactDOM from 'react-dom/client';
import './styles.css';

const MainDashboard = React.lazy(() =>
  import('./components/MainDashboard').then((m) => ({ default: m.MainDashboard }))
);
const AlertPopup = React.lazy(() =>
  import('./components/AlertPopup').then((m) => ({ default: m.AlertPopup }))
);

const isAlertRoute = window.location.hash.includes('alert');
if (isAlertRoute) {
  document.documentElement.classList.add('transparent-root');
  document.body.classList.add('transparent-root');
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Suspense fallback={null}>{isAlertRoute ? <AlertPopup /> : <MainDashboard />}</Suspense>
  </React.StrictMode>
);
