(ns build
  (:require [clojure.tools.build.api :as b]
            [clojure.edn :as edn]
            [clojure.string :as str]))

(def project (-> (edn/read-string (slurp "deps.edn")) :aliases :neil :project))
(def rev (str/trim (b/git-process {:git-args "rev-parse HEAD"})))
(def lib (:name project))
(def version (:version project))
(def license-id (-> project :license :id))
(def license-file (or (-> project :license :file) "LICENSE"))
(def description (:description project))
(def repo-url-prefix (:url project (-> (b/git-process {:git-args "remote get-url origin"})
                                       (str/trim)
                                       (str/replace #"\.git$" ""))))
(assert lib ":name must be set in deps.edn under the :neil alias")
(assert version ":version must be set in deps.edn under the :neil alias")
(assert description ":description must be set in deps.edn under the :neil alias")
(assert license-id "[:license :id] must be set in deps.edn under the :neil alias")
(def class-dir "target/classes")
(def basis_ (delay (b/create-basis {:project "deps.edn"})))
(def jar-file (format "target/%s-%s.jar" (name lib) version))

(defn permalink [subpath]
  (str repo-url-prefix "/blob/" rev "/" subpath))

(defn url->scm [url-string]
  (let [[_ domain repo-path] (re-find #"https?://?([\w\-\.]+)/(.+)" url-string)]
    [:scm
     [:url (str "https://" domain "/")]
     [:connection (str "scm:git:https://" domain "/" repo-path)]
     [:developerConnection (str "scm:git:ssh:git@" domain ":" repo-path)]]))

(defn clean [_]
  (b/delete {:path "target"}))

(defn jar [_]
  (b/write-pom {:class-dir class-dir
                :lib lib
                :version version
                :basis @basis_
                :src-dirs ["src"]
                :pom-data [[:description description]
                           [:url repo-url-prefix]
                           [:licenses
                            [:license
                             [:name license-id]
                             [:url (permalink license-file)]]]
                           (conj (url->scm repo-url-prefix) [:tag (str "v" version)])]})

  (b/copy-dir {:src-dirs ["src" "resources"]
               :target-dir class-dir})
  (b/jar {:class-dir class-dir
          :jar-file jar-file}))

(defn install [_]
  (jar {})
  (b/install {:basis @basis_
              :lib lib
              :version version
              :jar-file jar-file
              :class-dir class-dir}))

(defn deploy [opts]
  (jar opts)
  ((requiring-resolve 'deps-deploy.deps-deploy/deploy)
   (merge {:installer :remote
           :artifact jar-file
           :pom-file (b/pom-path {:lib lib :class-dir class-dir})}
          opts))
  opts)
