# Exercícios Aula 05 - Protegendo branches e implementando segurança de código

Antes de começar faça um fork desse repositório para sua conta pessoal. Você pode fazer isso clicando no botão `Fork` no canto superior direito da página.

## Exercício 1 - Implementando segurança de código

Vamos ativar o GitHub Actions para que o código seja analisado a partir de um workflow. Para isso, siga os seguintes passos:

1. Vá na aba `Actions` do seu repositório e clique no botão verde `I understand my workflows, go ahead and enable them`
   1. :warning: Caso não apareça essa opção, siga para o próximo passo

Em seguida vamos ativar o `Dependabot` para que as dependências do projeto sejam atualizadas automaticamente. Para isso, siga os seguintes passos:

2. Vá na aba de `Settings` do seu repositório e clique em `Security & analysis`
3. Na seção `Dependabot` em `Dependabot alerts` clique em `Enable`
4. Em `Dependabot security updates` clique em `Enable`
5. Aguarde alguns segundos até que o `Dependabot` possa processar o seu repositório e vá na aba `Security` do seu repositório e clique em `Dependabot alerts` para verificar se o `Dependabot` está funcionando corretamente

Em seguida vamos ativar o `CodeQL` para que o código seja analisado a cada push e pull request. Para isso, siga os seguintes passos:

5. Vá na aba de `Settings` do seu repositório e clique em `Security & analysis`
6. Na seção `Code scanning` em `CodeQL Analysis` clique em `Set up` e selecione `Advanced`
7. Você será redirecionado para uma nova página com um workflow pré criado para você. Não é necessário fazer nenhuma modificação no arquivo, mas busque entender o que ele faz. Clique em `Commit changes` e em seguida, novamente em `Commit changes`

Agora vamos adicionar a revisão de dependências (Dependency Review) para que, a cada novo Pull Request, seja feita uma análise de segurança das dependências (bibliotecas) do projeto. Para isso, siga os seguintes passos:

8. Vá na aba de `Settings` do seu repositório e clique em `Security & analysis` > `Explore workflows` e selecione o workflow `Dependency Review`
   1. :warning: Tente entender o que esse workflow faz
9.  Salve o workflow clicanco em `Commit changes` e em seguida, novamente em `Commit changes`

## Exercício 2 - Protegendo branches

1. Adicione o usuário `pedrolacerda` como colaborador do seu repositório
   1. Para adicionar um novo colaborador, vá até a página de configurações do seu repositório (`Settings`), clique em `Collaborators`, `Add people` e adicione o usuário `pedrolacerda`
2. Adicione um arquivo `CODEOWNERS` no repositório para que o usuário `@pedrolacerda` e o seu próprio usuário como donos do código. Para isso, crie um arquivo `CODEOWNERS` na raiz do repositório com o seguinte conteúdo:
   
   ```
   *     @pedrolacerda @<seu_usuario>
   ```
   - :warning: Não esqueça de substituir `<seu_usuario>` pelo seu usuário do GitHub
   
3. Implemente a proteção do branch `master` para que ele só possa ser alterado por você
   1. Para proteger o branch `master`, vá até a página de configurações do seu repositório (`Settings`), clique em `Branches` e selecione `Add branch protection rule`
   2. Em `Branch name pattern` digite `master`
   3. Marque o checkbox `Require pull request reviews before merging`
   4. Marque `Require approvals` e selecione a opção `1`
   5. Marque a opção `Dismiss stale pull request approvals when new commits are pushed`
   6. Marque a opção `Require review from Code Owners`
4. Adicione uma validação obrigatória para o CodeQL
   1. Marque o checkbox `Require status checks to pass before merging`, depois clique no checkbox `Require branches to be up to date before merging`.
   2. Na caixa de texto, busque por `Analyze` e selecione a opção `Analyze (javascript)`
   3. Isso fará com que os Pull Requests tenham, necessariamente, que avaliar se a aplicação não contém vulnerabilidades de Javascript e, caso tenha, bloqueia o merge
5. Faça uma modificação no `README.md` (pode inserir qualquer texto) e faça o commit
   1. :warning: **Você pode criar um novo branch antes de fazer a ediçao do `README.md` ou criar um novo branch no momento do commit**
6. Crie um pull request para o branch `master` e adicione o usuário `@pedrolacerda` como revisor
   1. :warning: **Nós vimos como criar um pull request no exercício da aula 04. Não se esqueça de selecionar o seu próprio repositório como base para o pull request**
