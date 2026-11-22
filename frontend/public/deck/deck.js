(function () {
  var deck = document.getElementById('deck');
  var slides = Array.prototype.slice.call(deck.children);
  var notes = document.getElementById('notes');
  var pos = document.getElementById('pos');
  var cur = -1;

  function fit() {
    var s = Math.min(window.innerWidth / 1920, window.innerHeight / 1080);
    deck.style.transform = 'scale(' + s + ')';
  }

  function stopFilm(slide) {
    var film = slide && slide.querySelector('.film');
    if (film && film.dataset.poster) {
      film.innerHTML = film.dataset.poster;
      delete film.dataset.poster;
    }
  }

  function go(n) {
    n = Math.max(0, Math.min(slides.length - 1, n));
    if (n === cur) return;
    if (cur >= 0) {
      slides[cur].classList.remove('on');
      stopFilm(slides[cur]);
    }
    cur = n;
    slides[cur].classList.add('on');
    var aside = slides[cur].querySelector('aside');
    notes.textContent = aside ? aside.textContent : '';
    pos.textContent = (cur + 1) + ' / ' + slides.length;
    if (location.hash !== '#' + (cur + 1)) history.replaceState(null, '', '#' + (cur + 1));
  }

  document.addEventListener('keydown', function (e) {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    var k = e.key;
    if (k === 'ArrowRight' || k === 'PageDown' || k === ' ' || k === 'Enter') { e.preventDefault(); go(cur + 1); }
    else if (k === 'ArrowLeft' || k === 'PageUp' || k === 'Backspace') { e.preventDefault(); go(cur - 1); }
    else if (k === 'Home') go(0);
    else if (k === 'End') go(slides.length - 1);
    else if (k === 'f' || k === 'F') {
      if (document.fullscreenElement) document.exitFullscreen();
      else document.documentElement.requestFullscreen();
    }
    else if (k === 'n' || k === 'N') document.body.classList.toggle('notes');
  });

  deck.addEventListener('click', function (e) {
    var film = e.target.closest('.film');
    if (film) {
      e.preventDefault();
      if (!film.dataset.poster) {
        film.dataset.poster = film.innerHTML;
        film.innerHTML = '<iframe src="https://www.youtube-nocookie.com/embed/' + film.dataset.yt +
          '?autoplay=1&rel=0&modestbranding=1" allow="autoplay; encrypted-media; picture-in-picture; fullscreen" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>';
      }
      return;
    }
    if (e.target.closest('a, iframe')) return;
    go(e.clientX < window.innerWidth / 3 ? cur - 1 : cur + 1);
  });

  var tx = null;
  document.addEventListener('touchstart', function (e) { tx = e.touches[0].clientX; }, { passive: true });
  document.addEventListener('touchend', function (e) {
    if (tx === null) return;
    var dx = e.changedTouches[0].clientX - tx;
    if (Math.abs(dx) > 50) go(dx < 0 ? cur + 1 : cur - 1);
    tx = null;
  });

  window.addEventListener('resize', fit);
  window.addEventListener('hashchange', function () { go((parseInt(location.hash.slice(1), 10) || 1) - 1); });
  fit();
  go((parseInt(location.hash.slice(1), 10) || 1) - 1);
})();
