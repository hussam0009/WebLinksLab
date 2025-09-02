// Force all links to open in a new tab
document.querySelectorAll("a").forEach((link) => {
    link.setAttribute("target", "_blank");
  });
  
  // Optional: Handle dynamic content (e.g., JavaScript-rendered links)
  const observer = new MutationObserver(() => {
    document.querySelectorAll("a").forEach((link) => {
      if (!link.target) link.target = "_blank";
    });
  });
  observer.observe(document.body, { subtree: true, childList: true });