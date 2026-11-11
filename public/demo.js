const products = [
  { category: 'mouse', name: 'Draadloze muis', description: 'Stille draadloze muis met USB-ontvanger.', price: '€ 29,00' },
  { category: 'keyboard', name: 'Mechanisch toetsenbord', description: 'Compact toetsenbord met verwisselbare toetsen.', price: '€ 89,00' },
];
const query = new URLSearchParams(location.search);
const broken = query.get('scenario') === 'bug';
const grid = document.querySelector('#products');
const search = document.querySelector('#search');
const details = document.querySelector('#details');
const checkout = document.querySelector('#checkout-button');
let category = 'all';
let count = 0;

function render() {
  const term = search.value.trim().toLowerCase();
  const matches = products.filter(product =>
    (category === 'all' || product.category === category) && product.name.toLowerCase().includes(term));
  grid.replaceChildren();
  if (!matches.length) grid.textContent = 'Geen producten gevonden.';
  for (const product of matches) {
    const card = document.createElement('article');
    const heading = document.createElement('h2');
    heading.textContent = product.name;
    const price = document.createElement('p');
    price.textContent = product.price;
    const info = document.createElement('button');
    info.className = 'preset';
    info.textContent = 'Details';
    info.setAttribute('aria-label', `Details ${product.name.toLowerCase()}`);
    info.addEventListener('click', () => {
      details.querySelector('h2').textContent = product.name;
      details.querySelector('p').textContent = product.description;
      details.showModal();
    });
    const add = document.createElement('button');
    add.className = 'preset';
    add.textContent = 'In winkelwagen';
    add.addEventListener('click', () => {
      if (broken && product.category === 'mouse') return;
      count++;
      document.querySelector('[role="status"]').textContent =
        count === 1 ? '1 artikel in winkelwagen' : `${count} artikelen in winkelwagen`;
      checkout.disabled = false;
    });
    card.append(heading, price, info, add);
    grid.append(card);
  }
}

search.addEventListener('input', render);
const categories = [...document.querySelectorAll('[data-category]')];
for (const button of categories) {
  button.addEventListener('click', () => {
    category = button.dataset.category;
    for (const candidate of categories) {
      candidate.classList.toggle('selected', candidate === button);
      candidate.setAttribute('aria-pressed', candidate === button);
    }
    render();
  });
}
checkout.addEventListener('click', () => {
  document.querySelector('#shop').hidden = true;
  document.querySelector('#checkout').hidden = false;
});
render();
